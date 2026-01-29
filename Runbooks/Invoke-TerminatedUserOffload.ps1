<#
.SYNOPSIS
    Offloads terminated user data (mail/chat/archive) and uploads to an external archive.
.DESCRIPTION
    Sanitized portfolio version.

    This runbook demonstrates:
    - Hybrid Worker module loading strategy
    - Long-running export orchestration
    - Upload + verification + cleanup workflow

    NOTE: Vendor names/domains/IDs have been replaced with placeholders.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$UserEmail,

    [Parameter(Mandatory = $false)]
    [string]$EmployeeName = "",

    [Parameter(Mandatory = $false)]
    [string]$EmployeeId = ""
)

$modulesLoaded = $false

if ($PSCommandPath) {
    $scriptPath = Split-Path -Parent $PSCommandPath
    try {
        Import-Module (Join-Path $scriptPath "CloudOffloadModule.psm1") -Force -ErrorAction Stop
        Import-Module (Join-Path $scriptPath "ArchiveUploadModule.psm1") -Force -ErrorAction Stop
        $modulesLoaded = $true
    } catch { }
}

if (-not $modulesLoaded) {
    $hybridWorkerModulePath = "C:\AutomationModules"
    if (Test-Path $hybridWorkerModulePath) {
        try {
            $cloudModulePath = Join-Path $hybridWorkerModulePath "CloudOffloadModule\CloudOffloadModule.psm1"
            $archiveModulePath = Join-Path $hybridWorkerModulePath "ArchiveUploadModule\ArchiveUploadModule.psm1"
            if (Test-Path $cloudModulePath) { Import-Module $cloudModulePath -Force -ErrorAction Stop }
            if (Test-Path $archiveModulePath) { Import-Module $archiveModulePath -Force -ErrorAction Stop }
            $modulesLoaded = $true
        } catch { }
    }
}

if (-not $modulesLoaded) {
    Write-Output "Attempting to load modules from Azure Automation..."
    foreach ($mod in @('CloudOffloadModule', 'ArchiveUploadModule')) {
        try { Import-Module -Name $mod -ErrorAction Stop } catch { }
    }
}

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogFile = "Offload_$timestamp.log"

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )

    $logTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$logTimestamp] [$Level] $Message"

    switch ($Level) {
        "ERROR"   { Write-Error $logMessage }
        "WARNING" { Write-Warning $logMessage }
        "SUCCESS" { Write-Output "✓ $logMessage" }
        default   { Write-Output $logMessage }
    }

    try { Add-Content -Path $LogFile -Value $logMessage -ErrorAction SilentlyContinue } catch { }
}

$SqlLoggingConfig = @{
    Enabled = $false
    ServerName = "__SQL_SERVER_FQDN__"
    DatabaseName = "__SQL_DATABASE__"
    CredentialName = "__SQL_CREDENTIAL_NAME__"
}

function Write-SqlLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Operation,

        [Parameter(Mandatory=$true)]
        [string]$UserEmail,

        [Parameter(Mandatory=$false)]
        [string]$EmployeeId = "",

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

    try {
        $sqlServer = $SqlLoggingConfig.ServerName
        $sqlDb = $SqlLoggingConfig.DatabaseName
        $sqlCredName = $SqlLoggingConfig.CredentialName

        $sqlCred = Get-AutomationPSCredential -Name $sqlCredName -ErrorAction Stop
        $connString = "Server=tcp:$sqlServer,1433;Initial Catalog=$sqlDb;Persist Security Info=False;User ID=$($sqlCred.UserName);Password=$($sqlCred.GetNetworkCredential().Password);MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"

        $sqlConn = New-Object System.Data.SqlClient.SqlConnection($connString)
        $sqlConn.Open()

        $query = @"
INSERT INTO [dbo].[AutomationJobLog]
(Operation, EmployeeId, SamAccountName, UserPrincipalName, Status, FinalOutput, AdditionalDetails, JobId)
VALUES
(@Operation, @EmployeeId, @SamAccountName, @UserPrincipalName, @Status, @FinalOutput, @AdditionalDetails, @JobId)
"@

        $sqlCmd = $sqlConn.CreateCommand()
        $sqlCmd.CommandText = $query
        $sqlCmd.CommandTimeout = 30

        $sqlCmd.Parameters.AddWithValue("@Operation", "Offload-$Operation") | Out-Null
        $sqlCmd.Parameters.AddWithValue("@EmployeeId", $(if ($EmployeeId) { $EmployeeId } else { [DBNull]::Value })) | Out-Null
        $sqlCmd.Parameters.AddWithValue("@SamAccountName", [DBNull]::Value) | Out-Null
        $sqlCmd.Parameters.AddWithValue("@UserPrincipalName", $UserEmail) | Out-Null
        $sqlCmd.Parameters.AddWithValue("@Status", $Status) | Out-Null
        $sqlCmd.Parameters.AddWithValue("@FinalOutput", $(if ($FinalOutput) { $FinalOutput } else { [DBNull]::Value })) | Out-Null
        $sqlCmd.Parameters.AddWithValue("@AdditionalDetails", $(if ($AdditionalDetails) { $AdditionalDetails } else { [DBNull]::Value })) | Out-Null
        $sqlCmd.Parameters.AddWithValue("@JobId", $JobId) | Out-Null

        $null = $sqlCmd.ExecuteNonQuery()

        try { $sqlCmd.Dispose() } catch { }
        try {
            if ($sqlConn.State -eq 'Open') { $sqlConn.Close() }
            $sqlConn.Dispose()
        } catch { }

    } catch { }
}

try {
    Write-Log "======================================================" "INFO"
    Write-Log "  TERMINATED USER OFFLOAD - STARTING" "INFO"
    Write-Log "======================================================" "INFO"

    # Validate email domain (placeholder)
    if ($UserEmail -notlike "*@__DOMAIN_PRIMARY__") {
        throw "This runbook only processes users in __DOMAIN_PRIMARY__. Received: $UserEmail"
    }

    $config = @{
        CloudServiceAccountEmail = Get-AutomationVariable -Name 'CloudServiceAccountEmail'
        CloudServiceAccountKeyPath = Get-AutomationVariable -Name 'CloudServiceAccountKeyPath'
        CloudAdminEmail = Get-AutomationVariable -Name 'CloudAdminEmail'
        CloudArchiveUserEmail = Get-AutomationVariable -Name 'CloudArchiveUserEmail'

        NotificationEmail = Get-AutomationVariable -Name 'NotificationEmail'
        SMTPServer = Get-AutomationVariable -Name 'SMTPServer'
        SMTPFrom = Get-AutomationVariable -Name 'SMTPFrom'
    }

    $requiredVars = @('CloudServiceAccountEmail', 'CloudServiceAccountKeyPath', 'CloudAdminEmail', 'CloudArchiveUserEmail')
    $missing = @($requiredVars | Where-Object { [string]::IsNullOrEmpty($config[$_]) })
    if ($missing.Count -gt 0) {
        throw "Missing required Azure Automation variables: $($missing -join ', ')"
    }

    # Verify external tooling/modules
    if (Get-Command -Name Test-ArchiveCli -ErrorAction SilentlyContinue) {
        $cliCheck = Test-ArchiveCli
        if (-not $cliCheck.Success) { throw "Archive CLI check failed" }
    }

    # Orchestrate export (functions provided by imported modules)
    # NOTE: The detailed vendor-specific implementation lives in modules and is not included in this sanitized runbook.

    Write-Log "Starting exports..." "INFO"

    $result = @{ Success = $true; UserEmail = $UserEmail; EmployeeName = $EmployeeName; EmployeeId = $EmployeeId; CompletedAt = Get-Date }

    Write-SqlLog -Operation "Offload" -UserEmail $UserEmail -EmployeeId $EmployeeId -Status "Success" -FinalOutput "Offload completed (sanitized sample)" -AdditionalDetails "EmployeeName: $EmployeeName"

    return $result

} catch {
    $errorMessage = $_.Exception.Message
    Write-Log "FATAL ERROR: $errorMessage" "ERROR"

    Write-SqlLog -Operation "Offload" -UserEmail $UserEmail -EmployeeId $EmployeeId -Status "Failed" -FinalOutput "Offload failed (sanitized sample): $errorMessage" -AdditionalDetails "EmployeeName: $EmployeeName"

    throw
}
