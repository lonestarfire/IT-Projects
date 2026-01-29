<#
.SYNOPSIS
    Enable or disable email accounts based on status changes.
.DESCRIPTION
    Sanitized portfolio version.

    This runbook demonstrates:
    - Pulling secrets from Automation variables
    - OAuth refresh token flow
    - Safe request building and retries
    - Optional centralized logging

    Vendor-specific identifiers and domains have been replaced with placeholders.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$EmailAddress,

    [Parameter(Mandatory = $true)]
    [ValidateSet("Enable", "Disable")]
    [string]$Action,

    [Parameter(Mandatory = $false)]
    [string]$OrgId = "__MAIL_ORG_ID__"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$script:RunId = [guid]::NewGuid().ToString()
$script:LogSequence = 0
$script:LogBuffer = [System.Collections.ArrayList]::new()

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

function Get-AccessToken {
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
            $body = @{ refresh_token = $RefreshToken; client_id = $ClientId; client_secret = $ClientSecret; grant_type = "refresh_token" }
            $response = Invoke-RestMethod -Uri "__OAUTH_TOKEN_URL__" -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
            return $response.access_token
        } catch {
            $lastError = $_
            $isTransient = $_.Exception.Message -match "Unable to connect|timeout|temporarily unavailable|503|502|504"
            if ($isTransient -and $attempt -lt $maxRetries) {
                Start-Sleep -Seconds ($attempt * 5)
            } else {
                throw $lastError
            }
        }
    }
}

try {
    Write-Log "======================================"
    Write-Log "Mail Operation Runbook Started"
    Write-Log "======================================"
    Write-Log "Email: $EmailAddress"
    Write-Log "Action: $Action"

    # Retrieve secrets from Azure Automation
    $clientId = Get-AutomationVariable -Name "MailClientId"
    $clientSecret = Get-AutomationVariable -Name "MailClientSecret"
    $refreshToken = Get-AutomationVariable -Name "MailRefreshToken"

    if (-not $clientId -or -not $clientSecret -or -not $refreshToken) {
        throw "Missing one or more required Automation variables: MailClientId, MailClientSecret, MailRefreshToken"
    }

    $accessToken = Get-AccessToken -ClientId $clientId -ClientSecret $clientSecret -RefreshToken $refreshToken

    $headers = @{ "Authorization" = "Bearer $accessToken"; "Accept" = "application/json"; "Content-Type" = "application/json" }

    # Direct lookup by email
    $lookupUrl = "__MAIL_API_BASE_URL__/organization/$OrgId/accounts/$EmailAddress"
    $accountResponse = Invoke-RestMethod -Uri $lookupUrl -Method Get -Headers $headers

    $account = $accountResponse.data
    if ($account -is [System.Array]) { $account = $account[0] }

    if (-not $account -or -not $account.accountId) {
        throw "Account not found: $EmailAddress"
    }

    [long]$accountIdValue = $account.accountId
    [long]$zuidValue = $account.zuid

    $actionUrl = "__MAIL_API_BASE_URL__/organization/$OrgId/accounts/$accountIdValue"

    if ($Action -eq "Enable") {
        $body = "{`"zuid`":$zuidValue,`"mode`":`"enableUser`",`"unblockIncoming`":true}"
        $result = Invoke-RestMethod -Uri $actionUrl -Method Put -Headers $headers -Body $body
        if ($result.status.code -ne 200) { throw "Enable failed: $($result.status.description)" }
    } else {
        $body = "{`"zuid`":$zuidValue,`"mode`":`"disableUser`",`"unblockIncoming`":false}"
        $result = Invoke-RestMethod -Uri $actionUrl -Method Put -Headers $headers -Body $body
        if ($result.status.code -ne 200) { throw "Disable failed: $($result.status.description)" }
    }

    Write-Log "Operation completed" -Level "SUCCESS"

    return @{ Success = $true; EmailAddress = $EmailAddress; Action = $Action; RunId = $script:RunId }

} catch {
    Write-Log "Operation failed: $($_.Exception.Message)" -Level "ERROR"
    throw
}
