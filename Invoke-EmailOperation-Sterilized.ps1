<#
.SYNOPSIS
    Enable or disable email accounts via API integration.

.DESCRIPTION
    This runbook is triggered by Azure Logic App when a user's status changes in the HR system.
    It uses the email service API to enable or disable the user's email account.

.PARAMETER EmailAddress
    The email address of the user to enable/disable. Must end in @[DOMAIN]

.PARAMETER Action
    The action to perform: "Disable" or "Enable"

.PARAMETER OrganizationId
    (Optional) The organization ID. Defaults to [DEFAULT_ORG_ID].

.EXAMPLE
    Invoke-EmailOperation.ps1 -EmailAddress "john.doe@[DOMAIN]" -Action "Disable"

.NOTES
    Author: [Author Name]
    Date: [Date]
    Requires: Azure Automation account with encrypted variables for API credentials
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidatePattern('.*@\[DOMAIN\]$')]
    [string]$EmailAddress,

    [Parameter(Mandatory = $true)]
    [ValidateSet("Enable", "Disable")]
    [string]$Action,

    [Parameter(Mandatory = $false)]
    [string]$OrganizationId = "[DEFAULT_ORG_ID]"
)

#region Configuration
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Note: API URLs are hardcoded inline in functions to avoid Azure Automation
# variable scope/caching issues.
# - Email API: https://api.[EMAIL_SERVICE].com
# - Accounts API: https://accounts.[EMAIL_SERVICE].com

# SQL Logging Configuration (matches other runbooks)
$SqlLoggingConfig = @{
    Enabled = $true
    ServerName = "[SQL_SERVER].database.windows.net"
    DatabaseName = "[DATABASE_NAME]"
    CredentialName = "[SQL_CREDENTIAL_NAME]"
}

#endregion

#region Functions

# Script-level log buffer for Azure Table Storage
$script:LogBuffer = [System.Collections.ArrayList]::new()
$script:RunId = [guid]::NewGuid().ToString()
$script:LogSequence = 0

function Write-Log {
    <#
    .SYNOPSIS
        Writes structured log messages to console and maintains buffer for storage
    .DESCRIPTION
        Provides centralized logging functionality that writes to console output
        and maintains an in-memory buffer for later storage to Azure Table Storage.
        Supports different log levels with appropriate output stream routing.
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
    
    # Add to buffer for later storage
    $script:LogSequence++
    $null = $script:LogBuffer.Add(@{
        Timestamp = (Get-Date).ToUniversalTime().ToString("o")
        Level = $Level
        Message = $Message
        Sequence = $script:LogSequence
    })
    
    switch ($Level) {
        "ERROR"   { Write-Error $logMessage }
        "WARNING" { Write-Warning $logMessage }
        "SUCCESS" { Write-Output $logMessage }
        default   { Write-Output $logMessage }
    }
}

function Write-SqlLog {
    <#
    .SYNOPSIS
        Writes operation summary to Azure SQL Database for centralized logging
    .DESCRIPTION
        Logs email operations to SQL with proper error handling.
        SQL failures do not affect the main operation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Operation,
        
        [Parameter(Mandatory=$true)]
        [string]$EmailAddress,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet('Success', 'Failed', 'Skipped')]
        [string]$Status,
        
        [Parameter(Mandatory=$true)]
        [string]$FinalOutput,
        
        [Parameter(Mandatory=$false)]
        [string]$AdditionalDetails = "",
        
        [Parameter(Mandatory=$false)]
        [string]$JobId = $(try { $PSPrivateMetadata.JobId.Guid } catch { "local-$(Get-Date -Format 'yyyyMMddHHmmss')" })
    )
    
    if (-not $SqlLoggingConfig.Enabled) { return }
    
    $sqlConn = $null
    $sqlCmd = $null
    try {
        $sqlServer = $SqlLoggingConfig.ServerName
        $sqlDb = $SqlLoggingConfig.DatabaseName
        $sqlCredName = $SqlLoggingConfig.CredentialName
        
        if ($sqlServer -and $sqlDb -and $sqlCredName) {
            $sqlCred = Get-AutomationPSCredential -Name $sqlCredName -ErrorAction Stop
            
            if ($sqlCred) {
                $connString = "Server=tcp:$sqlServer,1433;Initial Catalog=$sqlDb;Persist Security Info=False;User ID=$($sqlCred.UserName);Password=$($sqlCred.GetNetworkCredential().Password);MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
                $sqlConn = New-Object System.Data.SqlClient.SqlConnection($connString)
                $sqlConn.Open()
                
                $query = @"
INSERT INTO [dbo].[AutomationJobLog] 
(Operation, EmployeeId, SamAccountName, UserPrincipalName, Status, FinalOutput, AdditionalDetails, JobId, RunbookName, InputParameters)
VALUES 
(@Operation, @EmployeeId, @SamAccountName, @UserPrincipalName, @Status, @FinalOutput, @AdditionalDetails, @JobId, @RunbookName, @InputParameters)
"@
                $sqlCmd = $sqlConn.CreateCommand()
                $sqlCmd.CommandText = $query
                $sqlCmd.CommandTimeout = 30
                
                # Build input parameters JSON for retry capability
                $inputParamsJson = "{`"EmailAddress`":`"$EmailAddress`",`"Action`":`"$Operation`"}"
                
                $sqlCmd.Parameters.AddWithValue("@Operation", "Email-$Operation") | Out-Null
                $sqlCmd.Parameters.AddWithValue("@EmployeeId", [DBNull]::Value) | Out-Null
                $sqlCmd.Parameters.AddWithValue("@SamAccountName", [DBNull]::Value) | Out-Null
                $sqlCmd.Parameters.AddWithValue("@UserPrincipalName", $EmailAddress) | Out-Null
                $sqlCmd.Parameters.AddWithValue("@Status", $Status) | Out-Null
                $sqlCmd.Parameters.AddWithValue("@FinalOutput", $(if ($FinalOutput) { $FinalOutput } else { [DBNull]::Value })) | Out-Null
                $sqlCmd.Parameters.AddWithValue("@AdditionalDetails", $(if ($AdditionalDetails) { $AdditionalDetails } else { [DBNull]::Value })) | Out-Null
                $sqlCmd.Parameters.AddWithValue("@JobId", $JobId) | Out-Null
                $sqlCmd.Parameters.AddWithValue("@RunbookName", "Invoke-EmailOperation") | Out-Null
                $sqlCmd.Parameters.AddWithValue("@InputParameters", $inputParamsJson) | Out-Null
                
                $rows = $sqlCmd.ExecuteNonQuery()
                
                if ($rows -gt 0) {
                    Write-Log "✓ SQL Audit logged to $sqlDb" -Level "INFO"
                }
            }
        }
    } catch {
        Write-Log "Warning: Failed to write SQL audit record: $($_.Exception.Message)" -Level "WARNING"
    } finally {
        # Ensure proper cleanup of SQL resources
        if ($sqlCmd) { 
            try { $sqlCmd.Dispose() } catch { }
        }
        if ($sqlConn) { 
            try { 
                if ($sqlConn.State -eq 'Open') { $sqlConn.Close() }
                $sqlConn.Dispose() 
            } catch { }
        }
    }
}

function Get-ServiceAccessToken {
    <#
    .SYNOPSIS
        Gets a fresh access token using the refresh token
    .DESCRIPTION
        Includes built-in retry logic for transient network errors (up to 3 attempts with exponential backoff)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientSecret,
        
        [Parameter(Mandatory = $true)]
        [string]$RefreshToken
    )
    
    $maxRetries = 3
    $lastError = $null
    
    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        try {
            if ($attempt -eq 1) {
                Write-Log "Requesting new access token from service..."
            } else {
                Write-Log "Retry attempt $attempt of $maxRetries for access token..."
            }
            
            $body = @{
                refresh_token = $RefreshToken
                client_id     = $ClientId
                client_secret = $ClientSecret
                grant_type    = "refresh_token"
            }
            
            # URL hardcoded to avoid any scope issues in Azure Automation
            $response = Invoke-RestMethod -Uri "https://accounts.[SERVICE].com/oauth/v2/token" -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
            
            Write-Log "Access token obtained successfully (expires in $($response.expires_in) seconds)" -Level "SUCCESS"
            return $response.access_token
            
        } catch {
            $lastError = $_
            $isTransientError = $_.Exception.Message -match "Unable to connect|timeout|temporarily unavailable|503|502|504"
            
            if ($isTransientError -and $attempt -lt $maxRetries) {
                $waitSeconds = $attempt * 5  # 5s, 10s, 15s backoff
                Write-Log "Transient error detected: $($_.Exception.Message)" -Level "WARNING"
                Write-Log "Waiting $waitSeconds seconds before retry..." -Level "WARNING"
                Start-Sleep -Seconds $waitSeconds
            } elseif ($attempt -eq $maxRetries) {
                Write-Log "Failed to obtain access token after $maxRetries attempts: $($_.Exception.Message)" -Level "ERROR"
                throw $lastError
            } else {
                # Non-transient error, fail immediately
                Write-Log "Failed to obtain access token: $($_.Exception.Message)" -Level "ERROR"
                throw
            }
        }
    }
}

#endregion

#region Main Execution

try {
    Write-Log "======================================"
    Write-Log "Email Operation Runbook Started"
    Write-Log "======================================"
    Write-Log "Email: $EmailAddress"
    Write-Log "Action: $Action"
    Write-Log " "
    
    # Step 1: Retrieve credentials from Azure Automation
    Write-Log "Retrieving service API credentials from Azure Automation..."
    
    try {
        $clientId = Get-AutomationVariable -Name "ServiceClientId"
        $clientSecret = Get-AutomationVariable -Name "ServiceClientSecret"
        $refreshToken = Get-AutomationVariable -Name "ServiceRefreshToken"

        if (-not $clientId -or -not $clientSecret -or -not $refreshToken) {
            throw "One or more required automation variables are missing or empty"
        }
        
        Write-Log "✓ Credentials retrieved successfully" -Level "SUCCESS"
        
    } catch {
        Write-Log "Failed to retrieve automation variables. Ensure the following variables are configured in Azure Automation:" -Level "ERROR"
        Write-Log "  - ServiceClientId" -Level "ERROR"
        Write-Log "  - ServiceClientSecret" -Level "ERROR"
        Write-Log "  - ServiceRefreshToken" -Level "ERROR"
        throw
    }
    
    # Step 2: Get access token
    $accessToken = Get-ServiceAccessToken -ClientId $clientId -ClientSecret $clientSecret -RefreshToken $refreshToken

    # Handle case where function returns an array (logs + token)
    if ($accessToken -is [System.Array]) {
        $accessToken = $accessToken[-1]
    }

    if ($null -eq $accessToken) {
        Write-Log "Access token is NULL" -Level "ERROR"
        throw "Failed to obtain access token"
    }
    
    # Step 3: Get account details by email address (direct lookup)
    Write-Log "Looking up account: $EmailAddress" -Level "INFO"
    
    try {
        $headers = @{
            "Authorization" = "Bearer $accessToken"
            "Accept" = "application/json"
            "Content-Type" = "application/json"
        }
        
        # Direct lookup by email - much faster than pagination!
        $lookupUrl = "https://api.[SERVICE].com/organization/$OrganizationId/accounts/$EmailAddress"
        Write-Log "  GET $lookupUrl"
        
        $response = Invoke-RestMethod -Uri $lookupUrl -Method Get -Headers $headers
        
        # Debug: Log the raw response structure
        Write-Log "  Response status code: $($response.status.code)"
        Write-Log "  Response status description: $($response.status.description)"
        Write-Log "  Response data type: $($response.data.GetType().Name)"
        
        if ($response.status.code -ne 200) {
            throw "API returned error: $($response.status.description)"
        }
        
        $account = $response.data
        
        # Handle case where data might be an array (API returns array even for single account)
        if ($account -is [System.Array]) {
            Write-Log "  Note: API returned array, taking first element"
            $account = $account[0]
        }
        
        if (-not $account -or -not $account.accountId) {
            Write-Log "  Account object: $($account | ConvertTo-Json -Compress -Depth 2)" -Level "WARNING"
            throw "Account not found: $EmailAddress"
        }
        
        Write-Log "✓ Account found!" -Level "SUCCESS"
        Write-Log "  - AccountId: $($account.accountId)"
        Write-Log "  - Display Name: $($account.displayName)"
        
    } catch {
        Write-Log "Failed to retrieve account: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
    
    # Step 4: Log current status
    $previousStatus = $account.status
    Write-Log "Current status: $previousStatus"

    # Step 5: Perform the action (INLINED to avoid Azure Automation function caching issues)
    Write-Log "Performing action: $Action..."
    Write-Log " "
    
    # Extract simple values to avoid deserialized object issues in Azure Automation
    [long]$accountIdValue = $account.accountId
    
    # Build URL directly (avoid intermediate variables that can become null)
    $actionUrl = "https://api.[SERVICE].com/organization/$OrganizationId/accounts/$accountIdValue"
    
    # Create headers hashtable inline
    $actionHeaders = @{
        "Authorization" = "Bearer $accessToken"
        "Accept" = "application/json"
        "Content-Type" = "application/json"
    }
    
    Write-Log "API URL: $actionUrl"
    Write-Log "AccountId: $accountIdValue"
    
    if ($Action -eq "Enable") {
        # ============================================================
        # ENABLE: Restore full access
        # ============================================================
        Write-Log "Checking current account settings..."
        
        # Current status from account lookup (already have this data)
        # Note: If a field is $null (not returned by API), we assume it needs to be enabled
        $needsUserEnable = ($account.status -eq $false) -or ($null -eq $account.status)
        
        Write-Log "  Current state:"
        Write-Log "    - User Status: $(if ($account.status) { 'Active' } else { 'Inactive' })"
        Write-Log " "
        
        $apiCallsMade = 0
        $apiCallsSkipped = 0
        
        # Enable User (sets status to Active)
        if ($needsUserEnable) {
            $body = "{`"accountId`":$accountIdValue,`"mode`":`"enableUser`"}"
            Write-Log "  Enabling user..."
            Write-Log "    Body: $body"
            $result = Invoke-RestMethod -Uri $actionUrl -Method Put -Headers $actionHeaders -Body $body
            if ($result.status.code -eq 200) {
                Write-Log "    ✓ Success" -Level "SUCCESS"
                $apiCallsMade++
            } else {
                throw "enableUser failed: $($result.status.description)"
            }
        } else {
            Write-Log "  Skipping enableUser - already active"
            $apiCallsSkipped++
        }
        
        Write-Log " "
        Write-Log "✓ User fully enabled!" -Level "SUCCESS"
        Write-Log "  - API calls made: $apiCallsMade"
        Write-Log "  - API calls skipped (already correct): $apiCallsSkipped"
        Write-Log "  - Note: UI may take ~5 min to reflect changes"
        
    } else {
        # ============================================================
        # DISABLE: Block user login but KEEP service active
        # ============================================================
        $body = "{`"accountId`":$accountIdValue,`"mode`":`"disableUser`"}"
        Write-Log "  Disabling user (status only, service keeps working)..."
        Write-Log "    Body: $body"
        $result = Invoke-RestMethod -Uri $actionUrl -Method Put -Headers $actionHeaders -Body $body
        if ($result.status.code -eq 200) {
            Write-Log "    ✓ Success" -Level "SUCCESS"
        } else {
            throw "disableUser failed: $($result.status.description)"
        }
        
        Write-Log " "
        Write-Log "✓ User disabled!" -Level "SUCCESS"
        Write-Log "  - User cannot login"
        Write-Log "  - Service account stays active (HR can still send emails)"
        Write-Log "  - Note: UI may take ~5 min to reflect changes"
    }

    # Step 6: Operation complete
    Write-Log "✓ Operation completed successfully" -Level "SUCCESS"
    Write-Log " "
    
    # Log success to SQL
    Write-SqlLog -Operation $Action `
        -EmailAddress $EmailAddress `
        -Status "Success" `
        -FinalOutput "Email account ${Action}d successfully" `
        -AdditionalDetails "PreviousStatus: $previousStatus"
    
    return @{
        Success = $true
        Message = "Account ${Action}d successfully"
        EmailAddress = $EmailAddress
        PreviousStatus = $previousStatus
        ActionTaken = $Action
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        RunId = $script:RunId
    }
    
} catch {
    Write-Log " "
    Write-Log "======================================"
    Write-Log "Operation Failed"
    Write-Log "======================================"
    Write-Log "Error: $($_.Exception.Message)" -Level "ERROR"
    
    # Log failure to SQL
    Write-SqlLog -Operation $Action `
        -EmailAddress $EmailAddress `
        -Status "Failed" `
        -FinalOutput "Email operation failed: $($_.Exception.Message)" `
        -AdditionalDetails "Action attempted: $Action"
    
    if ($_.Exception.Response) {
        try {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $responseBody = $reader.ReadToEnd()
            Write-Log "API Response: $responseBody" -Level "ERROR"
        } catch {
            Write-Log "Could not read API response body" -Level "ERROR"
        }
    }
    
    throw
}

#endregion
