# Update-BoxUserEmails.ps1 (Sanitized)
#
# Updates a user's email configuration in an external content platform.
# Secrets MUST NOT be hardcoded.

param (
    [Parameter(Mandatory = $true)]
    [string]$OldUPN,

    [Parameter(Mandatory = $true)]
    [string]$NewUPN,

    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [Parameter(Mandatory = $true)]
    [string]$ClientSecret,

    [Parameter(Mandatory = $true)]
    [string]$EnterpriseId,

    [Parameter(Mandatory = $true)]
    [string]$JwtKeyPath
)

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [ExternalPlatform] [$Level] $Message"

    $logsDir = Join-Path $PSScriptRoot "logs"
    if (-not (Test-Path $logsDir)) { New-Item -ItemType Directory -Path $logsDir | Out-Null }

    $date = Get-Date -Format "yyyy-MM-dd"
    $logFile = Join-Path $logsDir "platform_migration_log_$date.txt"
    $logMessage | Out-File -FilePath $logFile -Append -Encoding UTF8

    switch ($Level) {
        'Info'    { Write-Host $logMessage -ForegroundColor White }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
        'Success' { Write-Host $logMessage -ForegroundColor Green }
    }
}

function Get-AccessToken {
    $privateKey = Get-Content $JwtKeyPath -Raw

    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $exp = $now + 3600

    $header = @{ alg = "RS256"; typ = "JWT"; kid = $ClientId }
    $payload = @{ iss = $ClientId; sub = $EnterpriseId; aud = "__OAUTH_TOKEN_URL__"; jti = [guid]::NewGuid(); exp = $exp; iat = $now }

    $headerJson = $header | ConvertTo-Json -Compress
    $payloadJson = $payload | ConvertTo-Json -Compress

    $headerBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($headerJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    $payloadBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payloadJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_')

    $toSign = "$headerBase64.$payloadBase64"

    $rsa = [System.Security.Cryptography.RSA]::Create()
    $rsa.ImportFromPem($privateKey)

    $signature = $rsa.SignData([System.Text.Encoding]::UTF8.GetBytes($toSign), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $signatureBase64 = [Convert]::ToBase64String($signature).TrimEnd('=').Replace('+', '-').Replace('/', '_')

    $jwt = "$headerBase64.$payloadBase64.$signatureBase64"

    $tokenResponse = Invoke-RestMethod -Method Post -Uri "__OAUTH_TOKEN_URL__" -Body @{ grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"; assertion = $jwt; client_id = $ClientId; client_secret = $ClientSecret }
    return $tokenResponse.access_token
}

function Find-User {
    param([string]$Email, [string]$AccessToken)

    $headers = @{ "Authorization" = "Bearer $AccessToken" }
    $response = Invoke-RestMethod -Method Get -Uri "__PLATFORM_API_BASE_URL__/users?filter_term=$Email" -Headers $headers
    if ($response.total_count -gt 0) { return $response.entries[0] }
    return $null
}

function Update-UserEmails {
    param([string]$UserId, [string]$PrimaryEmail, [string]$NotificationEmail, [string]$AccessToken)

    $headers = @{ "Authorization" = "Bearer $AccessToken" }
    $body = @{ login = $PrimaryEmail; notification_email = @{ email = $NotificationEmail } } | ConvertTo-Json

    $response = Invoke-RestMethod -Method Put -Uri "__PLATFORM_API_BASE_URL__/users/$UserId" -Headers $headers -Body $body -ContentType "application/json"
    return $response
}

try {
    Write-Log "Starting email update process for: $OldUPN" -Level Info

    $accessToken = Get-AccessToken

    $user = Find-User -Email $OldUPN -AccessToken $accessToken
    if ($null -eq $user) {
        Write-Log "User not found. No changes needed." -Level Warning
        return
    }

    $updatedUser = Update-UserEmails -UserId $user.id -PrimaryEmail $NewUPN -NotificationEmail $OldUPN -AccessToken $accessToken

    Write-Log "Updated user email configuration." -Level Success
    Write-Log "Primary Email: $($updatedUser.login)" -Level Success
    Write-Log "Notification Email: $($updatedUser.notification_email.email)" -Level Success

} catch {
    Write-Log "Error: $_" -Level Error
    throw
}
