<#
.SYNOPSIS
    Retries failed automation operations from a centralized log.
.DESCRIPTION
    Sanitized portfolio version.

    Demonstrates:
    - Querying a log store for failed operations
    - Mapping stored parameters back into runbook invocations
    - Updating retry status

    SQL identifiers and automation account names replaced with placeholders.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [int]$MaxRetries = 3,

    [Parameter(Mandatory = $false)]
    [int]$LookbackHours = 24
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$SqlConfig = @{
    ServerName = "__SQL_SERVER_FQDN__"
    DatabaseName = "__SQL_DATABASE__"
    CredentialName = "__SQL_CREDENTIAL_NAME__"
}

$AutomationConfig = @{
    ResourceGroupName = "__RESOURCE_GROUP__"
    AutomationAccountName = "__AUTOMATION_ACCOUNT__"
}

$RetryableRunbooks = @{
    "Invoke-MailOperation" = @{ ParameterMapping = @{ "EmailAddress" = "EmailAddress"; "Action" = "Action" }; RunOn = $null }
    "Invoke-DirectoryUserOperation" = @{ ParameterMapping = @{ "WebhookData" = "InputParameters" }; RunOn = "__WORKER_GROUP_AD__" }
}

function Write-Log {
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
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$MaxRetries,

        [Parameter(Mandatory = $true)]
        [int]$LookbackHours
    )

    $sqlCred = Get-AutomationPSCredential -Name $SqlConfig.CredentialName -ErrorAction Stop
    $connString = "Server=tcp:$($SqlConfig.ServerName),1433;Initial Catalog=$($SqlConfig.DatabaseName);Persist Security Info=False;User ID=$($sqlCred.UserName);Password=$($sqlCred.GetNetworkCredential().Password);MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"

    $sqlConn = New-Object System.Data.SqlClient.SqlConnection($connString)
    $sqlConn.Open()

    $query = @"
SELECT LogID, Operation, RunbookName, InputParameters, UserPrincipalName, EmployeeId, SamAccountName, Status, FinalOutput, RetryCount, RetryStatus, Timestamp
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
    $results = @()

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

    try { $sqlCmd.Dispose() } catch { }
    try {
        if ($sqlConn.State -eq 'Open') { $sqlConn.Close() }
        $sqlConn.Dispose()
    } catch { }

    return $results
}

function Update-RetryStatus {
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

    $sqlCred = Get-AutomationPSCredential -Name $SqlConfig.CredentialName -ErrorAction Stop
    $connString = "Server=tcp:$($SqlConfig.ServerName),1433;Initial Catalog=$($SqlConfig.DatabaseName);Persist Security Info=False;User ID=$($sqlCred.UserName);Password=$($sqlCred.GetNetworkCredential().Password);MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"

    $sqlConn = New-Object System.Data.SqlClient.SqlConnection($connString)
    $sqlConn.Open()

    $updateParts = @("RetryStatus = @RetryStatus", "LastRetryAtUtc = GETUTCDATE()")
    if ($IncrementRetryCount) { $updateParts += "RetryCount = ISNULL(RetryCount, 0) + 1" }
    if ($AdditionalDetails) { $updateParts += "AdditionalDetails = ISNULL(AdditionalDetails, '') + ' | RETRY: ' + @AdditionalDetails" }
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
    if ($AdditionalDetails) { $sqlCmd.Parameters.AddWithValue("@AdditionalDetails", $AdditionalDetails) | Out-Null }

    $rows = $sqlCmd.ExecuteNonQuery()

    try { $sqlCmd.Dispose() } catch { }
    try {
        if ($sqlConn.State -eq 'Open') { $sqlConn.Close() }
        $sqlConn.Dispose()
    } catch { }

    return $rows -gt 0
}

function Invoke-RunbookRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RunbookName,

        [Parameter(Mandatory = $true)]
        [string]$InputParametersJson,

        [Parameter(Mandatory = $false)]
        [string]$RunOn = $null
    )

    $inputParams = $InputParametersJson | ConvertFrom-Json
    $runbookParams = @{}

    if ($RetryableRunbooks.ContainsKey($RunbookName)) {
        $mapping = $RetryableRunbooks[$RunbookName].ParameterMapping
        foreach ($targetParam in $mapping.Keys) {
            $sourceField = $mapping[$targetParam]
            if ($sourceField -eq "InputParameters") {
                $runbookParams[$targetParam] = $InputParametersJson
            } elseif ($inputParams.PSObject.Properties[$sourceField]) {
                $runbookParams[$targetParam] = $inputParams.$sourceField
            }
        }
    } else {
        foreach ($prop in $inputParams.PSObject.Properties) {
            $runbookParams[$prop.Name] = $prop.Value
        }
    }

    $jobParams = @{
        ResourceGroupName = $AutomationConfig.ResourceGroupName
        AutomationAccountName = $AutomationConfig.AutomationAccountName
        Name = $RunbookName
        Parameters = $runbookParams
        Wait = $true
        MaxWaitSeconds = 300
    }

    if ($RunOn) { $jobParams['RunOn'] = $RunOn }

    $job = Start-AzAutomationRunbook @jobParams

    return @{ Success = $job.Status -eq 'Completed'; Status = $job.Status; JobId = $job.JobId }
}

try {
    Write-Log "======================================"
    Write-Log "Retry Failed Operations Runbook Started"
    Write-Log "======================================"

    try {
        $connection = Get-AutomationConnection -Name "AzureRunAsConnection" -ErrorAction SilentlyContinue
        if ($connection) {
            Connect-AzAccount -ServicePrincipal -Tenant $connection.TenantId -ApplicationId $connection.ApplicationId -CertificateThumbprint $connection.CertificateThumbprint | Out-Null
        } else {
            Connect-AzAccount -Identity | Out-Null
        }
    } catch {
        throw "Failed to connect to Azure: $($_.Exception.Message)"
    }

    $failedOps = Get-FailedOperations -MaxRetries $MaxRetries -LookbackHours $LookbackHours
    if ($failedOps.Count -eq 0) {
        Write-Log "No failed operations found eligible for retry" -Level "SUCCESS"
        return
    }

    foreach ($op in $failedOps) {
        Write-Log "Processing LogID: $($op.LogID)"
        $isLastAttempt = ($op.RetryCount + 1) -ge $MaxRetries

        Update-RetryStatus -LogID $op.LogID -RetryStatus 'RETRY_IN_PROGRESS' | Out-Null

        $runOn = $null
        if ($RetryableRunbooks.ContainsKey($op.RunbookName)) {
            $runOn = $RetryableRunbooks[$op.RunbookName].RunOn
        }

        $result = Invoke-RunbookRetry -RunbookName $op.RunbookName -InputParametersJson $op.InputParameters -RunOn $runOn

        if ($result.Success) {
            Update-RetryStatus -LogID $op.LogID -RetryStatus 'RETRY_SUCCESS' -IncrementRetryCount -AdditionalDetails "Retry succeeded" | Out-Null
        } else {
            if ($isLastAttempt) {
                Update-RetryStatus -LogID $op.LogID -RetryStatus 'PERMANENTLY_FAILED' -IncrementRetryCount -AdditionalDetails "Max retries reached" | Out-Null
            } else {
                Update-RetryStatus -LogID $op.LogID -RetryStatus 'RETRY_FAILED' -IncrementRetryCount -AdditionalDetails "Retry failed" | Out-Null
            }
        }
    }

} catch {
    Write-Log "Retry Runbook Failed: $($_.Exception.Message)" -Level "ERROR"
    throw
}
