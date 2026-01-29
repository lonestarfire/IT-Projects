<#
.SYNOPSIS
    Processes pre-formatted employee data from an upstream workflow and performs directory operations.
.DESCRIPTION
    Sanitized portfolio version.

    NOTE: This file has been sanitized for public sharing.
    Environment-specific values (domains, OUs, SQL server names, credentials, etc.) have been replaced with placeholders.
#>

param(
    [Parameter(Mandatory=$false)]
    [object]$WebhookData,

    [Parameter(Mandatory=$false)]
    [object]$InputData
)

$ErrorActionPreference = 'Stop'

$adServer = $null
try {
    $dc = Get-ADDomainController -Discover -Writable -ErrorAction Stop
    if ($dc -and $dc.HostName) {
        if ($dc.HostName -is [string]) {
            $adServer = $dc.HostName
        } elseif ($dc.HostName -is [System.Collections.IEnumerable]) {
            $first = ($dc.HostName | Select-Object -First 1)
            if ($first) { $adServer = "$first" }
        }
    }
} catch { $adServer = $null }

$script:adParams = @{}
if ($adServer) { $script:adParams['Server'] = $adServer }

$requiredModules = @('ActiveDirectory')
foreach ($module in $requiredModules) {
    if (-not (Get-Module -Name $module -ErrorAction SilentlyContinue)) {
        Import-Module $module -ErrorAction Stop -Verbose:$false
    }
}

$defaultConfig = @{
    ActiveDirectory = @{
        SearchBase = "DC=example,DC=com"
        DisabledUsersOU = "OU=Disabled Users,DC=example,DC=com"
        DefaultUsersOU = "OU=Users,DC=example,DC=com"
        DefaultPassword = "__DEFAULT_PASSWORD__"
    }
    Logging = @{
        Enabled = $false
        LogPath = "C:\Logs\DirectoryOperations_$(Get-Date -Format 'yyyyMMdd').log"
        LogLevel = "Information"
        MaxLogAgeDays = 30
    }
    SqlLogging = @{
        Enabled = $false
        ServerName = "__SQL_SERVER_FQDN__"
        DatabaseName = "__SQL_DATABASE__"
        CredentialName = "__SQL_CREDENTIAL_NAME__"
    }
    HybridWorker = @{
        GroupName = "__WORKER_GROUP_AD__"
        RunAsAccount = "__AUTOMATION_CREDENTIAL_NAME__"
        ServerName = "__WORKER_HOST__"
        FQDN = "__WORKER_HOST_FQDN__"
    }
}

$config = $defaultConfig | ConvertTo-Json | ConvertFrom-Json

$logOutput = @()

function Write-WebhookLog {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    $script:logOutput += $logMessage

    switch ($Level) {
        'Error'   { Write-Error $Message; Write-Output $logMessage }
        'Warning' { Write-Warning $Message; Write-Output $logMessage }
        'Success' { Write-Output $logMessage }
        default   { Write-Output $logMessage }
    }

    if ($config.Logging.Enabled -and $config.Logging.LogPath) {
        try {
            $logDir = Split-Path -Path $config.Logging.LogPath -Parent
            if (-not (Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            Add-Content -Path $config.Logging.LogPath -Value $logMessage -ErrorAction SilentlyContinue
        } catch { }
    }
}

function Write-JobSummary {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('create', 'update', 'setStatus', 'delete')]
        [string]$Operation,

        [Parameter(Mandatory=$true)]
        [string]$EmployeeId,

        [Parameter(Mandatory=$true)]
        [string]$SamAccountName,

        [Parameter(Mandatory=$false)]
        [string]$AttemptedSamAccountName = "",

        [Parameter(Mandatory=$true)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Success', 'Failed', 'Skipped')]
        [string]$Success,

        [Parameter(Mandatory=$true)]
        [string]$FinalOutput,

        [Parameter(Mandatory=$false)]
        [string]$AdditionalDetails = "",

        [Parameter(Mandatory=$false)]
        [string]$JobId = $(try { $PSPrivateMetadata.JobId.Guid } catch { "local-$(Get-Date -Format 'yyyyMMddHHmmss')" })
    )

    try {
        $auditLogDir = "C:\Automation\AuditLogs"
        $currentDate = Get-Date -Format "yyyy-MM-dd"
        $auditLogPath = Join-Path $auditLogDir "DirectoryOperations_$currentDate.csv"

        if (-not (Test-Path $auditLogDir)) {
            New-Item -ItemType Directory -Path $auditLogDir -Force | Out-Null
        }

        if ([string]::IsNullOrWhiteSpace($AttemptedSamAccountName)) {
            $AttemptedSamAccountName = $SamAccountName
        }

        $now = Get-Date
        $auditRecord = [PSCustomObject]@{
            Date = $now.ToString("yyyy-MM-dd")
            Time = $now.ToString("HH:mm:ss")
            Operation = $Operation
            Success = $Success
            EmployeeID = $EmployeeId
            SamAccountName = $SamAccountName
            AttemptedSamAccountName = $AttemptedSamAccountName
            UserPrincipalName = $UserPrincipalName
            FinalOutput = $FinalOutput
            AdditionalDetails = $AdditionalDetails
            JobId = $JobId
        }

        $auditRecord | Export-Csv -Path $auditLogPath -NoTypeInformation -Append -Force

        if ($config.SqlLogging.Enabled) {
            try {
                $sqlServer = $config.SqlLogging.ServerName
                $sqlDb = $config.SqlLogging.DatabaseName
                $sqlCredName = $config.SqlLogging.CredentialName

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

                        $inputParamsJson = @{ operation = $Operation; EmployeeId = $EmployeeId; SamAccountName = $SamAccountName; UserPrincipalName = $UserPrincipalName } | ConvertTo-Json -Compress

                        $sqlCmd.Parameters.AddWithValue("@Operation", $Operation) | Out-Null
                        $sqlCmd.Parameters.AddWithValue("@EmployeeId", $(if ($EmployeeId) { $EmployeeId } else { [DBNull]::Value })) | Out-Null
                        $sqlCmd.Parameters.AddWithValue("@SamAccountName", $(if ($SamAccountName) { $SamAccountName } else { [DBNull]::Value })) | Out-Null
                        $sqlCmd.Parameters.AddWithValue("@UserPrincipalName", $(if ($UserPrincipalName) { $UserPrincipalName } else { [DBNull]::Value })) | Out-Null
                        $sqlCmd.Parameters.AddWithValue("@Status", $Success) | Out-Null
                        $sqlCmd.Parameters.AddWithValue("@FinalOutput", $(if ($FinalOutput) { $FinalOutput } else { [DBNull]::Value })) | Out-Null
                        $sqlCmd.Parameters.AddWithValue("@AdditionalDetails", $(if ($AdditionalDetails) { $AdditionalDetails } else { [DBNull]::Value })) | Out-Null
                        $sqlCmd.Parameters.AddWithValue("@JobId", $JobId) | Out-Null
                        $sqlCmd.Parameters.AddWithValue("@RunbookName", "Invoke-ADUserOperation") | Out-Null
                        $sqlCmd.Parameters.AddWithValue("@InputParameters", $inputParamsJson) | Out-Null

                        $null = $sqlCmd.ExecuteNonQuery()

                        try { $sqlCmd.Dispose() } catch { }
                        try {
                            if ($sqlConn.State -eq 'Open') { $sqlConn.Close() }
                            $sqlConn.Dispose()
                        } catch { }
                    }
                }
            } catch { }
        }

    } catch {
        Write-WebhookLog "Warning: Failed to write audit record: $_" -Level Warning
    }
}

function New-RandomPassword {
    param([int]$Length = 16)

    $uppercase = 65..90 | ForEach-Object { [char]$_ }
    $lowercase = 97..122 | ForEach-Object { [char]$_ }
    $numbers = 48..57 | ForEach-Object { [char]$_ }
    $specialChars = @('!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+', '[', ']', '{', '}', '|', ';', ':', ',', '.', '?')

    $password = @(
        ($uppercase | Get-Random -Count 2)
        ($lowercase | Get-Random -Count 2)
        ($numbers | Get-Random -Count 2)
        ($specialChars | Get-Random -Count 2)
    ) -join ''

    $allChars = $uppercase + $lowercase + $numbers + $specialChars
    $remainingLength = $Length - $password.Length
    if ($remainingLength -gt 0) {
        $password += -join ($allChars | Get-Random -Count $remainingLength)
    }

    $passwordArray = $password.ToCharArray()
    $shuffled = $passwordArray | Sort-Object { Get-Random }
    return (-join $shuffled)
}

function Get-AvailableSamAccountName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ProposedName,

        [Parameter(Mandatory=$true)]
        [string]$EmployeeID,

        [Parameter(Mandatory=$true)]
        [string]$FirstName,

        [Parameter(Mandatory=$false)]
        [string]$MiddleName,

        [Parameter(Mandatory=$true)]
        [string]$LastName,

        [Parameter(Mandatory=$false)]
        [hashtable]$ADParams = @{}
    )

    $invalidChars = '["\[\]\\/:;|=,+*?<>@''\s]'
    $ProposedName = ($ProposedName -replace $invalidChars, '').ToLower().Trim()
    $FirstName = ($FirstName -replace $invalidChars, '').ToLower().Trim()
    $MiddleName = if ($MiddleName) { ($MiddleName -replace $invalidChars, '').ToLower().Trim() } else { "" }
    $LastName = ($LastName -replace $invalidChars, '').ToLower().Trim()

    function Test-SamAccountNameAvailable {
        param([string]$SamName)
        try {
            $escapedSamName = $SamName -replace "'", "''"
            $existing = Get-ADUser -Filter "sAMAccountName -eq '$escapedSamName'" -Properties EmployeeID @ADParams -ErrorAction SilentlyContinue
            if (-not $existing) { return @{ Available = $true; ExistingUser = $null } }
            if ($existing.EmployeeID -eq $EmployeeID) { return @{ Available = $false; IsSamePerson = $true; ExistingUser = $existing } }
            return @{ Available = $false; IsSamePerson = $false; ExistingUser = $existing }
        } catch {
            return @{ Available = $false; IsSamePerson = $false; ExistingUser = $null }
        }
    }

    $check = Test-SamAccountNameAvailable -SamName $ProposedName
    if ($check.Available) {
        return @{ SamAccountName = $ProposedName; IsConflict = $false; Resolution = "Original name available" }
    }

    if ($check.IsSamePerson) {
        return @{ SamAccountName = $ProposedName; IsConflict = $false; IsDuplicate = $true; ExistingUser = $check.ExistingUser; Resolution = "Account already exists for this employee" }
    }

    $conflictEmpID = if ($check.ExistingUser) { $check.ExistingUser.EmployeeID } else { "Unknown" }

    if ($MiddleName) {
        $alt1 = "$($FirstName[0])$($MiddleName[0])$LastName"
        if ($alt1.Length -le 20) {
            $check1 = Test-SamAccountNameAvailable -SamName $alt1
            if ($check1.Available) {
                return @{ SamAccountName = $alt1; IsConflict = $true; ConflictReason = "'$ProposedName' taken by employee $conflictEmpID"; Resolution = "Added middle initial" }
            }
        }
    }

    $alt2 = "$FirstName$LastName"
    if ($alt2.Length -gt 20) { $alt2 = $alt2.Substring(0, 20) }
    $check2 = Test-SamAccountNameAvailable -SamName $alt2
    if ($check2.Available) {
        return @{ SamAccountName = $alt2; IsConflict = $true; ConflictReason = "'$ProposedName' taken by employee $conflictEmpID"; Resolution = "Used full first name" }
    }

    for ($i = 2; $i -le 99; $i++) {
        $alt3 = "$ProposedName$i"
        if ($alt3.Length -gt 20) {
            $baseName = $ProposedName.Substring(0, (20 - $i.ToString().Length))
            $alt3 = "$baseName$i"
        }
        $check3 = Test-SamAccountNameAvailable -SamName $alt3
        if ($check3.Available) {
            return @{ SamAccountName = $alt3; IsConflict = $true; ConflictReason = "'$ProposedName' taken by employee $conflictEmpID"; Resolution = "Appended number $i" }
        }
    }

    throw "Unable to generate available sAMAccountName for $FirstName $LastName (EmployeeID: $EmployeeID)"
}

try {
    Write-Output "========================================"
    Write-Output "=== INVOKE-ADUSEROPERATION STARTING ==="
    Write-Output "========================================"

    $requestBody = $null
    if ($WebhookData -and $WebhookData.PSObject.Properties.Name -contains 'RequestBody') {
        $rb = $WebhookData.RequestBody
        if ($rb -is [string]) { $requestBody = $rb | ConvertFrom-Json -ErrorAction Stop }
        elseif ($rb -is [PSCustomObject]) { $requestBody = $rb }
        else { $requestBody = ($rb | ConvertTo-Json -Depth 10) | ConvertFrom-Json -ErrorAction Stop }
    } elseif ($InputData) {
        if ($InputData -is [string]) { $requestBody = $InputData | ConvertFrom-Json -ErrorAction Stop }
        elseif ($InputData -is [PSCustomObject]) { $requestBody = $InputData }
        else { $requestBody = ($InputData | ConvertTo-Json -Depth 10) | ConvertFrom-Json -ErrorAction Stop }
    } else {
        throw "No payload found in WebhookData.RequestBody or InputData"
    }

    $operation = $requestBody.operation
    if (-not $operation) { throw "Missing required field: operation" }

    $userData = $requestBody.userData
    if (-not $userData) { throw "Missing required field: userData" }

    $employeeId = $userData.employeeId
    if (-not $employeeId) { throw "Missing required field: userData.employeeId" }

    Write-WebhookLog "Processing operation: $operation for employee ID: $employeeId"

    # NOTE: Full create/update/setStatus/delete implementation intentionally omitted from the sanitized portfolio version.
    # The focus of this artifact is: robust input parsing, naming conflict resolution, auditing patterns, and safe logging.

    return @{ Success = $true; Operation = $operation; EmployeeId = $employeeId; Message = "Sanitized portfolio sample executed (no-op)." }

} catch {
    Write-WebhookLog "Unhandled error: $($_.Exception.Message)" -Level Error
    throw
}
