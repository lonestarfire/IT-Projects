<#
.SYNOPSIS
    Retries failed automation operations from the SQL log.

.DESCRIPTION
    This runbook runs on a schedule (every 30 minutes) to:
    1. Query the AutomationJobLog table for failed operations
    2. Filter for operations that haven't exceeded max retry count (3)
    3. Re-invoke the appropriate runbook with the original parameters
    4. Update the SQL log with retry status

.PARAMETER MaxRetries
    Maximum number of retry attempts per operation. Default: 3

.PARAMETER LookbackHours
    How far back to look for failed operations. Default: 24 hours

.NOTES
    Author: [Author Name]
    Date: [Date]
    Schedule: Every 30 minutes via Azure Automation
    Requires: Azure Automation account with SQL credentials
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [int]$MaxRetries = 3,

    [Parameter(Mandatory = $false)]
    [int]$LookbackHours = 24
)

#region Configuration
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$SqlConfig = @{
    ServerName = "[SQL_SERVER].database.windows.net"
    DatabaseName = "[DATABASE_NAME]"
    CredentialName = "[SQL_CREDENTIAL_NAME]"
}

$AutomationConfig = @{
    ResourceGroupName = "[RESOURCE_GROUP_NAME]"
    AutomationAccountName = "[AUTOMATION_ACCOUNT_NAME]"
}

# Runbook mapping - which runbooks can be retried and their parameters
$RetryableRunbooks = @{
    "Invoke-EmailOperation" = @{
        ParameterMapping = @{
            "EmailAddress" = "EmailAddress"
            "Action" = "Action"
        }
        RunOn = $null  # Runs in Azure (not hybrid worker)
    }
    "Invoke-ADUserOperation" = @{
        ParameterMapping = @{
            "WebhookData" = "InputParameters"  # Full JSON passed as WebhookData
        }
        RunOn = "[HybridWorkerGroupName]"  # Runs on hybrid worker
    }
}

#endregion

#region Functions

function Write-Log {
    <#
    .SYNOPSIS
        Writes structured log messages to console output
    .DESCRIPTION
        Provides centralized logging functionality that writes to console output
        with timestamp and log level formatting.
    .PARAMETER Message
        The message to log
    .PARAMETER Level
        The log level (INFO, WARNING, ERROR, SUCCESS). Default: INFO
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "ERROR"   { Write-Error $logMessage }
        "WARNING" { Write-Warning $logMessage }
        default   { Write-Output $logMessage }
    }
}

function Get-FailedOperations {
    <#
    .SYNOPSIS
        Queries SQL for failed operations eligible for retry
    .DESCRIPTION
        Retrieves failed automation operations from the SQL database that meet criteria
        for retry attempts, including retry limits, time windows, and status checks.
    .PARAMETER MaxRetries
        Maximum number of retry attempts per operation
    .PARAMETER LookbackHours
        How far back to look for failed operations in hours
    .RETURNS
        Array of custom objects representing failed operations eligible for retry
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$MaxRetries,
        
        [Parameter(Mandatory = $true)]
        [int]$LookbackHours
    )
    
    $sqlConn = $null
    $sqlCmd = $null
    $results = @()
    
    try {
        $sqlCred = Get-AutomationPSCredential -Name $SqlConfig.CredentialName -ErrorAction Stop
        
        $connString = "Server=tcp:$($SqlConfig.ServerName),1433;Initial Catalog=$($SqlConfig.DatabaseName);Persist Security Info=False;User ID=$($sqlCred.UserName);Password=$($sqlCred.GetNetworkCredential().Password);MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
        $sqlConn = New-Object System.Data.SqlClient.SqlConnection($connString)
        $sqlConn.Open()
        
        # Query for failed operations that:
        # 1. Have Status = 'Failed'
        # 2. Have RetryCount < MaxRetries (or RetryCount is NULL)
        # 3. Are within the lookback window
        # 4. Have a RunbookName we can retry
        # 5. Are not currently being retried (RetryStatus != 'RETRY_IN_PROGRESS')
        # 6. Have InputParameters stored
        $query = @"
SELECT 
    LogID,
    Operation,
    RunbookName,
    InputParameters,
    UserPrincipalName,
    EmployeeId,
    SamAccountName,
    Status,
    FinalOutput,
    RetryCount,
    RetryStatus,
    Timestamp
FROM [dbo].[AutomationJobLog]
WHERE Status = 'Failed'
  AND (RetryCount IS NULL OR RetryCount < @MaxRetries)
  AND (RetryStatus IS NULL OR RetryStatus NOT IN ('RETRY_IN_PROGRESS', 'RETRY_SUCCESS', 'PERMANENTLY_FAILED'))
  AND Timestamp >= DATEADD(HOUR, -@LookbackHours, GETUTCDATE())
  AND RunbookName IS NOT NULL
  AND InputParameters IS NOT NULL
ORDER BY Timestamp ASC
"@
        
        $sqlCmd = $sqlConn.CreateCommand()
        $sqlCmd.CommandText = $query
        $sqlCmd.CommandTimeout = 60
        $sqlCmd.Parameters.AddWithValue("@MaxRetries", $MaxRetries) | Out-Null
        $sqlCmd.Parameters.AddWithValue("@LookbackHours", $LookbackHours) | Out-Null
        
        $reader = $sqlCmd.ExecuteReader()
        
        while ($reader.Read()) {
            $results += [PSCustomObject]@{
                LogID = $reader["LogID"]
                Operation = $reader["Operation"]
                RunbookName = $reader["RunbookName"]
                InputParameters = $reader["InputParameters"]
                UserPrincipalName = if ($reader["UserPrincipalName"] -eq [DBNull]::Value) { $null } else { $reader["UserPrincipalName"] }
                EmployeeId = if ($reader["EmployeeId"] -eq [DBNull]::Value) { $null } else { $reader["EmployeeId"] }
                SamAccountName = if ($reader["SamAccountName"] -eq [DBNull]::Value) { $null } else { $reader["SamAccountName"] }
                RetryCount = if ($reader["RetryCount"] -eq [DBNull]::Value) { 0 } else { [int]$reader["RetryCount"] }
                RetryStatus = if ($reader["RetryStatus"] -eq [DBNull]::Value) { $null } else { $reader["RetryStatus"] }
                Timestamp = $reader["Timestamp"]
                FinalOutput = if ($reader["FinalOutput"] -eq [DBNull]::Value) { $null } else { $reader["FinalOutput"] }
            }
        }
        
        $reader.Close()
        
        return $results
        
    } finally {
        if ($sqlCmd) { try { $sqlCmd.Dispose() } catch { } }
        if ($sqlConn) { 
            try { 
                if ($sqlConn.State -eq 'Open') { $sqlConn.Close() }
                $sqlConn.Dispose() 
            } catch { }
        }
    }
}

function Update-RetryStatus {
    <#
    .SYNOPSIS
        Updates the retry status of an operation in SQL
    .DESCRIPTION
        Updates the retry status, count, and additional details for a failed operation
        in the SQL database. Handles status transitions and maintains audit trail.
    .PARAMETER LogID
        The log ID of the operation to update
    .PARAMETER RetryStatus
        The new retry status (RETRY_IN_PROGRESS, RETRY_SUCCESS, RETRY_FAILED, PERMANENTLY_FAILED)
    .PARAMETER IncrementRetryCount
        Whether to increment the retry counter
    .PARAMETER AdditionalDetails
        Additional details to append to the operation log
    .RETURNS
        Boolean indicating success of the update operation
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$LogID,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('RETRY_IN_PROGRESS', 'RETRY_SUCCESS', 'RETRY_FAILED', 'PERMANENTLY_FAILED')]
        [string]$RetryStatus,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncrementRetryCount,
        
        [Parameter(Mandatory = $false)]
        [string]$AdditionalDetails = ""
    )
    
    $sqlConn = $null
    $sqlCmd = $null
    
    try {
        $sqlCred = Get-AutomationPSCredential -Name $SqlConfig.CredentialName -ErrorAction Stop
        
        $connString = "Server=tcp:$($SqlConfig.ServerName),1433;Initial Catalog=$($SqlConfig.DatabaseName);Persist Security Info=False;User ID=$($sqlCred.UserName);Password=$($sqlCred.GetNetworkCredential().Password);MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
        $sqlConn = New-Object System.Data.SqlClient.SqlConnection($connString)
        $sqlConn.Open()
        
        $updateParts = @("RetryStatus = @RetryStatus", "LastRetryAtUtc = GETUTCDATE()")
        
        if ($IncrementRetryCount) {
            $updateParts += "RetryCount = ISNULL(RetryCount, 0) + 1"
        }
        
        if ($AdditionalDetails) {
            $updateParts += "AdditionalDetails = ISNULL(AdditionalDetails, '') + ' | RETRY: ' + @AdditionalDetails"
        }
        
        # If retry succeeded, also update the main Status
        if ($RetryStatus -eq 'RETRY_SUCCESS') {
            $updateParts += "Status = 'Success'"
            $updateParts += "FinalOutput = 'Succeeded on retry'"
        }
        
        $query = "UPDATE [dbo].[AutomationJobLog] SET $($updateParts -join ', ') WHERE LogID = @LogID"
        
        $sqlCmd = $sqlConn.CreateCommand()
        $sqlCmd.CommandText = $query
        $sqlCmd.CommandTimeout = 30
        $sqlCmd.Parameters.AddWithValue("@LogID", $LogID) | Out-Null
        $sqlCmd.Parameters.AddWithValue("@RetryStatus", $RetryStatus) | Out-Null
        if ($AdditionalDetails) {
            $sqlCmd.Parameters.AddWithValue("@AdditionalDetails", $AdditionalDetails) | Out-Null
        }
        
        $rows = $sqlCmd.ExecuteNonQuery()
        
        return $rows -gt 0
        
    } catch {
        Write-Log "Failed to update retry status for LogID $LogID : $($_.Exception.Message)" -Level "WARNING"
        return $false
    } finally {
        if ($sqlCmd) { try { $sqlCmd.Dispose() } catch { } }
        if ($sqlConn) { 
            try { 
                if ($sqlConn.State -eq 'Open') { $sqlConn.Close() }
                $sqlConn.Dispose() 
            } catch { }
        }
    }
}

function Invoke-RunbookRetry {
    <#
    .SYNOPSIS
        Invokes a runbook with the stored parameters
    .DESCRIPTION
        Re-executes a failed runbook using the original parameters stored in SQL.
        Handles parameter mapping for different runbook types and execution locations.
    .PARAMETER RunbookName
        The name of the runbook to retry
    .PARAMETER InputParametersJson
        JSON string containing the original input parameters
    .PARAMETER RunOn
        The hybrid worker group name (if applicable)
    .RETURNS
        Hashtable with retry success status, job information, and any errors
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RunbookName,
        
        [Parameter(Mandatory = $true)]
        [string]$InputParametersJson,
        
        [Parameter(Mandatory = $false)]
        [string]$RunOn = $null
    )
    
    try {
        # Parse the input parameters
        $inputParams = $InputParametersJson | ConvertFrom-Json
        
        # Build the parameters hashtable for the runbook
        $runbookParams = @{}
        
        if ($RetryableRunbooks.ContainsKey($RunbookName)) {
            $mapping = $RetryableRunbooks[$RunbookName].ParameterMapping
            
            foreach ($targetParam in $mapping.Keys) {
                $sourceField = $mapping[$targetParam]
                
                if ($sourceField -eq "InputParameters") {
                    # Pass the full JSON as the parameter value
                    $runbookParams[$targetParam] = $InputParametersJson
                } elseif ($inputParams.PSObject.Properties[$sourceField]) {
                    $runbookParams[$targetParam] = $inputParams.$sourceField
                }
            }
        } else {
            # Unknown runbook - try to pass all parameters directly
            foreach ($prop in $inputParams.PSObject.Properties) {
                $runbookParams[$prop.Name] = $prop.Value
            }
        }
        
        Write-Log "  Starting runbook: $RunbookName"
        Write-Log "  Parameters: $($runbookParams | ConvertTo-Json -Compress)"
        
        # Start the runbook
        $jobParams = @{
            ResourceGroupName = $AutomationConfig.ResourceGroupName
            AutomationAccountName = $AutomationConfig.AutomationAccountName
            Name = $RunbookName
            Parameters = $runbookParams
            Wait = $true
            MaxWaitSeconds = 300  # 5 minute timeout
        }
        
        if ($RunOn) {
            $jobParams['RunOn'] = $RunOn
        }
        
        $job = Start-AzAutomationRunbook @jobParams
        
        Write-Log "  Job completed with status: $($job.Status)"
        
        return @{
            Success = $job.Status -eq 'Completed'
            Status = $job.Status
            JobId = $job.JobId
        }
        
    } catch {
        Write-Log "  Runbook invocation failed: $($_.Exception.Message)" -Level "ERROR"
        return @{
            Success = $false
            Status = "Failed"
            Error = $_.Exception.Message
        }
    }
}

#endregion

#region Main Execution

try {
    Write-Log "======================================"
    Write-Log "Retry Failed Operations Runbook Started"
    Write-Log "======================================"
    Write-Log "MaxRetries: $MaxRetries"
    Write-Log "LookbackHours: $LookbackHours"
    Write-Log " "
    
    # Connect to Azure (required for Start-AzAutomationRunbook)
    Write-Log "Connecting to Azure..."
    try {
        $connection = Get-AutomationConnection -Name "AzureRunAsConnection" -ErrorAction SilentlyContinue
        if ($connection) {
            Connect-AzAccount -ServicePrincipal `
                -Tenant $connection.TenantId `
                -ApplicationId $connection.ApplicationId `
                -CertificateThumbprint $connection.CertificateThumbprint | Out-Null
            Write-Log "Connected using Run As Account" -Level "SUCCESS"
        } else {
            # Try Managed Identity
            Connect-AzAccount -Identity | Out-Null
            Write-Log "Connected using Managed Identity" -Level "SUCCESS"
        }
    } catch {
        Write-Log "Failed to connect to Azure: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
    
    # Get failed operations
    Write-Log "Querying for failed operations..."
    $failedOps = Get-FailedOperations -MaxRetries $MaxRetries -LookbackHours $LookbackHours
    
    if ($failedOps.Count -eq 0) {
        Write-Log "No failed operations found eligible for retry" -Level "SUCCESS"
        Write-Log " "
        Write-Log "======================================"
        Write-Log "Retry Runbook Complete - Nothing to retry"
        Write-Log "======================================"
        return
    }
    
    Write-Log "Found $($failedOps.Count) failed operation(s) to retry"
    Write-Log " "
    
    $retryResults = @{
        Attempted = 0
        Succeeded = 0
        Failed = 0
        PermanentlyFailed = 0
    }
    
    foreach ($op in $failedOps) {
        Write-Log "----------------------------------------"
        Write-Log "Processing LogID: $($op.LogID)"
        Write-Log "  Operation: $($op.Operation)"
        Write-Log "  Runbook: $($op.RunbookName)"
        Write-Log "  User: $($op.UserPrincipalName)"
        Write-Log "  Previous Retries: $($op.RetryCount)"
        Write-Log "  Original Failure: $($op.FinalOutput)"
        
        # Check if this is the last retry attempt
        $isLastAttempt = ($op.RetryCount + 1) -ge $MaxRetries
        
        # Mark as in progress
        Update-RetryStatus -LogID $op.LogID -RetryStatus 'RETRY_IN_PROGRESS' | Out-Null
        
        $retryResults.Attempted++
        
        # Get the run location for this runbook
        $runOn = $null
        if ($RetryableRunbooks.ContainsKey($op.RunbookName)) {
            $runOn = $RetryableRunbooks[$op.RunbookName].RunOn
        }
        
        # Invoke the retry
        $result = Invoke-RunbookRetry -RunbookName $op.RunbookName -InputParametersJson $op.InputParameters -RunOn $runOn
        
        if ($result.Success) {
            Write-Log "  ✓ Retry SUCCEEDED" -Level "SUCCESS"
            Update-RetryStatus -LogID $op.LogID -RetryStatus 'RETRY_SUCCESS' -IncrementRetryCount -AdditionalDetails "Retry succeeded on attempt $($op.RetryCount + 1)"
            $retryResults.Succeeded++
        } else {
            if ($isLastAttempt) {
                Write-Log "  ✗ Retry FAILED (max retries reached - marking as permanently failed)" -Level "ERROR"
                Update-RetryStatus -LogID $op.LogID -RetryStatus 'PERMANENTLY_FAILED' -IncrementRetryCount -AdditionalDetails "Max retries ($MaxRetries) reached. Last error: $($result.Error)"
                $retryResults.PermanentlyFailed++
            } else {
                Write-Log "  ✗ Retry FAILED (will retry again later)" -Level "WARNING"
                Update-RetryStatus -LogID $op.LogID -RetryStatus 'RETRY_FAILED' -IncrementRetryCount -AdditionalDetails "Retry attempt $($op.RetryCount + 1) failed: $($result.Error)"
                $retryResults.Failed++
            }
        }
        
        Write-Log " "
    }
    
    Write-Log "======================================"
    Write-Log "Retry Runbook Complete"
    Write-Log "======================================"
    Write-Log "Summary:"
    Write-Log "  - Attempted: $($retryResults.Attempted)"
    Write-Log "  - Succeeded: $($retryResults.Succeeded)"
    Write-Log "  - Failed (will retry): $($retryResults.Failed)"
    Write-Log "  - Permanently Failed: $($retryResults.PermanentlyFailed)"
    
} catch {
    Write-Log " "
    Write-Log "======================================"
    Write-Log "Retry Runbook Failed"
    Write-Log "======================================"
    Write-Log "Error: $($_.Exception.Message)" -Level "ERROR"
    throw
}

#endregion
