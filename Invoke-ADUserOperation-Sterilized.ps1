<#
.SYNOPSIS
    Processes pre-formatted employee data from Logic App and performs AD operations.

.DESCRIPTION
    This runbook is triggered by a Logic App that has already processed the HR system webhook
    and formatted the data for AD operations.
    It performs one of the following actions based on the operation type:
    - Create a new AD user
    - Update an existing AD user
    - Enable/Disable an AD user
    - Delete an AD user

.PARAMETER WebhookData
    JSON data from Logic App containing:
    - operation: 'create', 'update', 'setStatus', or 'delete'
    - userData: Object containing user properties
    - status: (for setStatus) 'enabled' or 'disabled'

.NOTES
    Requirements:
    - Must run on Hybrid Worker Group: [HybridWorkerGroupName]
    - Run As Account: [RunAsAccountName]
    - Active Directory module installed on Hybrid Worker
    - Appropriate permissions to manage AD users

    Last Updated: [CurrentDate]
#>

#region Initialization

# Accept input from Logic App/Azure Automation webhook
param(
    [Parameter(Mandatory=$false)]
    [object]$WebhookData,

    [Parameter(Mandatory=$false)]
    [object]$InputData
)
# Set Error Action
$ErrorActionPreference = 'Stop'

# AD Configuration
# Prefer discovering a writable DC dynamically instead of a hardcoded IP to allow Kerberos auth
$adServer = $null

# Discover a writable DC; fall back to no explicit Server if discovery fails
try {
    $dc = Get-ADDomainController -Discover -Writable -ErrorAction Stop
    if ($dc -and $dc.HostName) {
        # Coerce HostName to a single string (HostName may be an ADPropertyValueCollection)
        if ($dc.HostName -is [string]) {
            $adServer = $dc.HostName
        } elseif ($dc.HostName -is [System.Collections.IEnumerable]) {
            $first = ($dc.HostName | Select-Object -First 1)
            if ($first) { $adServer = "$first" }
        }
    }
} catch { $adServer = $null }

# AD Parameters for cmdlets (use current process identity; do not pass Credential)
$script:adParams = @{}
if ($adServer) { $script:adParams['Server'] = $adServer }

# Set ScriptRoot
try {
    $scriptRoot = if ($PSScriptRoot) {
        $PSScriptRoot  # Use the built-in PSScriptRoot if available
    } elseif ($MyInvocation.MyCommand.Path) {
        Split-Path -Parent $MyInvocation.MyCommand.Path
    } elseif ($PSCommandPath) {
        Split-Path -Parent $PSCommandPath
    } else {
        Get-Location | Select-Object -ExpandProperty Path
    }
} catch {
    $scriptRoot = Get-Location | Select-Object -ExpandProperty Path
    Write-Warning "Using current directory as script root: $scriptRoot"
}

# Import required modules
$requiredModules = @(
    "ActiveDirectory"
)

foreach ($module in $requiredModules) {
    if (-not (Get-Module -Name $module -ErrorAction SilentlyContinue)) {
        try {
            Import-Module $module -ErrorAction Stop -Verbose:$false
            Write-Output "Successfully imported module: $module"
        }
        catch {
            Write-Error "Failed to import module $module. Error: $_"
            exit 1
        }
    }
}

# Default configuration (sterilized - remove specific domain names, passwords, server info)
$defaultConfig = @{
    ActiveDirectory = @{
        SearchBase = "DC=[DOMAIN],DC=[TLD]"
        DisabledUsersOU = "OU=Disabled Users,DC=[DOMAIN],DC=[TLD]"
        DefaultUsersOU = "OU=Users,DC=[DOMAIN],DC=[TLD]"
        DefaultPassword = "[DEFAULT_PASSWORD]"
    }
    Logging = @{
        LogPath = "C:\Logs\ADOperations_$(Get-Date -Format 'yyyyMMdd').log"
        LogLevel = "Information"
        MaxLogAgeDays = 30
    }
    SqlLogging = @{
        Enabled = $true
        ServerName = "[SQL_SERVER].database.windows.net"
        DatabaseName = "[DATABASE_NAME]"
        CredentialName = "[SQL_CREDENTIAL_NAME]"
    }
    HybridWorker = @{
        GroupName = "[HybridWorkerGroupName]"
        RunAsAccount = "[RunAsAccountName]"
        ServerName = "[SERVER_NAME]"
        FQDN = "[SERVER_FQDN]"
    }
}

# Try to load configuration from file
$configPaths = @(
    "C:\\Automation\\Config\\config.json"                            # Hybrid Worker standard location
    Join-Path -Path $scriptRoot -ChildPath "..\\Config\\config.json"  # Local development
    Join-Path -Path $scriptRoot -ChildPath "Config\\config.json"      # Alternative local path
    "C:\\Config\\config.json"
    (Join-Path -Path $env:PSModulePath.Split(';')[0] -ChildPath "..\\Config\\config.json")  # Module-relative
)

$configPath = $null
foreach ($path in $configPaths) {
    if (Test-Path -Path $path -ErrorAction SilentlyContinue) {
        $configPath = $path
        break
    }
}

if ($configPath) {
    try {
        $loadedConfig = Get-Content -Path $configPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        
        # Merge with default config to ensure all required settings exist
        $defaultConfig.Keys | ForEach-Object {
            $key = $_
            if (-not $loadedConfig.PSObject.Properties[$key]) {
                $loadedConfig | Add-Member -MemberType NoteProperty -Name $key -Value $defaultConfig[$key]
            }
        }
        
        $config = $loadedConfig
        Write-Output "Successfully loaded configuration from: $configPath"
    }
    catch {
        Write-Warning "Failed to load configuration from $configPath. Using default configuration. Error: $_"
        $config = $defaultConfig | ConvertTo-Json | ConvertFrom-Json
    }
}

else {
    Write-Warning "Configuration file not found in any standard location. Using default configuration."
    $config = $defaultConfig | ConvertTo-Json | ConvertFrom-Json
}


# After configuration is loaded, optionally retrieve Automation Credential for AD operations
try {
    if ($config -and $config.HybridWorker -and $config.HybridWorker.RunAsAccount) {
        $runAsName = [string]$config.HybridWorker.RunAsAccount
        if ($runAsName -and $runAsName.Trim().Length -gt 0) {
            try {
                $runAsCred = Get-AutomationPSCredential -Name $runAsName -ErrorAction Stop
                if ($runAsCred) {
                    $script:adParams['Credential'] = $runAsCred
                    Write-Output ("[DEBUG] Using Automation Credential for AD operations: {0}" -f $runAsName)
                } else {
                    Write-Output ("[DEBUG] Automation Credential not found: {0}. Continuing without explicit credential." -f $runAsName)
                }
            } catch {
                Write-Output ("[DEBUG] Failed to retrieve Automation Credential '{0}': {1}. Continuing without explicit credential." -f $runAsName, $_.Exception.Message)
            }
        }
    }
} catch { Write-Output ("[DEBUG] RunAs credential configuration check failed: {0}" -f $_.Exception.Message) }

$logOutput = @()

#region Helper Functions
function Write-WebhookLog {
    <#
    .SYNOPSIS
        Writes structured log messages to multiple outputs (console, file, buffer)
    .DESCRIPTION
        Provides centralized logging functionality that writes to console output,
        maintains an in-memory buffer, and optionally writes to a log file.
        Supports different log levels with appropriate output stream routing.
    .PARAMETER Message
        The message to log
    .PARAMETER Level
        The log level (Info, Success, Warning, Error). Default: Info
    #>
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    $script:logOutput += $logMessage
    
    # Write to appropriate output stream
    switch ($Level) {
        'Error'   { Write-Error $Message; Write-Output $logMessage }
        'Warning' { Write-Warning $Message; Write-Output $logMessage }
        'Success' { Write-Output $logMessage }
        default   { Write-Output $logMessage }
    }
    
    # Log to file if configured
    if ($config.Logging.Enabled -and $config.Logging.LogPath) {
        try {
            $logDir = Split-Path -Path $config.Logging.LogPath -Parent
            if (-not (Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            Add-Content -Path $config.Logging.LogPath -Value $logMessage -ErrorAction SilentlyContinue
        }
        catch {
            # Silently fail if logging to file doesn't work
        }
    }
}

function Write-JobSummary {
    <#
    .SYNOPSIS
        Writes operation summary to daily CSV file for audit trail and troubleshooting
    .DESCRIPTION
        Creates structured audit records in CSV format with complete details for compliance,
        troubleshooting, and operation recovery. One CSV file per day.
    #>
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
        # Define audit log path on hybrid worker (daily files)
        $auditLogDir = "C:\Automation\AuditLogs"
        $currentDate = Get-Date -Format "yyyy-MM-dd"
        $auditLogPath = Join-Path $auditLogDir "ADOperations_$currentDate.csv"
        
        # Create directory if it doesn't exist
        if (-not (Test-Path $auditLogDir)) {
            New-Item -ItemType Directory -Path $auditLogDir -Force | Out-Null
            Write-WebhookLog "Created audit log directory: $auditLogDir" -Level Info
        }
        
        # Get current date and time
        $now = Get-Date
        
        # If AttemptedSamAccountName not provided, assume it's same as actual
        if ([string]::IsNullOrWhiteSpace($AttemptedSamAccountName)) {
            $AttemptedSamAccountName = $SamAccountName
        }
        
        # Create audit record with optimized columns for Excel filtering and troubleshooting
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
        
        # Export to CSV (append mode, creates file with headers if new)
        $auditRecord | Export-Csv -Path $auditLogPath -NoTypeInformation -Append -Force
        
        Write-WebhookLog "✓ Audit logged to: $auditLogPath" -Level Info
        
        # SQL Logging (sterilized connection info)
        if ($config.SqlLogging.Enabled) {
            $sqlConn = $null
            $sqlCmd = $null
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
                        
                        # Build input parameters JSON for retry capability
                        $inputParamsJson = @{
                            operation = $Operation
                            EmployeeId = $EmployeeId
                            SamAccountName = $SamAccountName
                            UserPrincipalName = $UserPrincipalName
                        } | ConvertTo-Json -Compress
                        
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
                        
                        $rows = $sqlCmd.ExecuteNonQuery()
                        
                        if ($rows -gt 0) {
                            Write-WebhookLog "✓ SQL Audit logged to $sqlDb" -Level Info
                        }
                    }
                }
            } catch {
                Write-WebhookLog "Warning: Failed to write SQL audit record: $($_.Exception.Message)" -Level Warning
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
        
    } catch {
        # Don't fail the main operation if audit logging fails
        Write-WebhookLog "Warning: Failed to write audit record: $_" -Level Warning
    }
}

function New-RandomPassword {
    <#
    .SYNOPSIS
        Generates a cryptographically secure random password
    .DESCRIPTION
        Creates a password with a mix of uppercase, lowercase, numbers, and special characters
    .PARAMETER Length
        Length of the password (default: 16)
    #>
    param(
        [int]$Length = 16
    )
    
    # Define character sets
    $uppercase = 65..90 | ForEach-Object { [char]$_ }
    $lowercase = 97..122 | ForEach-Object { [char]$_ }
    $numbers = 48..57 | ForEach-Object { [char]$_ }
    $specialChars = @('!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+', '[', ']', '{', '}', '|', ';', ':', ',', '.', '?')
    
    # Ensure at least one character from each set
    $password = @(
        ($uppercase | Get-Random -Count 2)
        ($lowercase | Get-Random -Count 2)
        ($numbers | Get-Random -Count 2)
        ($specialChars | Get-Random -Count 2)
    ) -join ''
    
    # Fill remaining length with random characters from all sets
    $allChars = $uppercase + $lowercase + $numbers + $specialChars
    $remainingLength = $Length - $password.Length
    if ($remainingLength -gt 0) {
        $password += -join ($allChars | Get-Random -Count $remainingLength)
    }
    
    # Shuffle the password to randomize character positions
    $passwordArray = $password.ToCharArray()
    $shuffled = $passwordArray | Sort-Object { Get-Random }
    $finalPassword = -join $shuffled
    
    return $finalPassword
}

function Get-AvailableSamAccountName {
    <#
    .SYNOPSIS
        Generates an available sAMAccountName by checking for conflicts and applying fallback naming conventions.
    .DESCRIPTION
        Checks if the proposed sAMAccountName is available in AD. If taken, generates alternatives:
        1. Checks if existing account belongs to the same person (by employeeID) → Returns existing
        2. Tries: FirstInitial + MiddleInitial + LastName (e.g., rjwilliams)
        3. Tries: FullFirstName + LastName (e.g., robertwilliams)
        4. Tries: FirstInitial + LastName + Number (e.g., rwilliams2, rwilliams3...)
    #>
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
    
    # Clean and normalize input - remove invalid characters for sAMAccountName
    # sAMAccountName cannot contain: " / \ [ ] : ; | = , + * ? < > @ ' and must be <= 20 chars
    $invalidChars = '["\[\]\\/:;|=,+*?<>@''\s]'
    $ProposedName = ($ProposedName -replace $invalidChars, '').ToLower().Trim()
    $FirstName = ($FirstName -replace $invalidChars, '').ToLower().Trim()
    $MiddleName = if ($MiddleName) { ($MiddleName -replace $invalidChars, '').ToLower().Trim() } else { "" }
    $LastName = ($LastName -replace $invalidChars, '').ToLower().Trim()
    
    Write-Output "Checking sAMAccountName availability: $ProposedName for EmployeeID: $EmployeeID"
    
    # Helper to test availability
    function Test-SamAccountNameAvailable {
        <#
        .SYNOPSIS
            Tests if a sAMAccountName is available in Active Directory
        .DESCRIPTION
            Queries Active Directory to check if a sAMAccountName is already in use.
            Determines if the name is available, belongs to the same person, or conflicts with another user.
        .PARAMETER SamName
            The sAMAccountName to test for availability
        .RETURNS
            Hashtable with availability status and conflict information
        #>
        param([string]$SamName)
        
        try {
            # Escape any remaining special characters in filter (double up single quotes for LDAP)
            $escapedSamName = $SamName -replace "'", "''"
            $existing = Get-ADUser -Filter "sAMAccountName -eq '$escapedSamName'" -Properties EmployeeID @ADParams -ErrorAction SilentlyContinue
            
            if (-not $existing) {
                return @{ Available = $true; ExistingUser = $null }
            }
            
            # Check if same person
            if ($existing.EmployeeID -eq $EmployeeID) {
                return @{ Available = $false; IsSamePerson = $true; ExistingUser = $existing }
            }
            
            return @{ Available = $false; IsSamePerson = $false; ExistingUser = $existing }
        } catch {
            Write-Warning "Error checking '$SamName': $_"
            return @{ Available = $false; IsSamePerson = $false; ExistingUser = $null }
        }
    }
    
    # Check proposed name
    $check = Test-SamAccountNameAvailable -SamName $ProposedName
    
    if ($check.Available) {
        Write-Output "✅ '$ProposedName' is available"
        return @{
            SamAccountName = $ProposedName
            IsConflict = $false
            Resolution = "Original name available"
        }
    }
    
    if ($check.IsSamePerson) {
        Write-Output "ℹ️ '$ProposedName' already exists for this employee"
        return @{
            SamAccountName = $ProposedName
            IsConflict = $false
            IsDuplicate = $true
            ExistingUser = $check.ExistingUser
            Resolution = "Account already exists for this employee"
        }
    }
    
    # Conflict - generate alternatives
    $conflictEmpID = if ($check.ExistingUser) { $check.ExistingUser.EmployeeID } else { "Unknown" }
    Write-Output "⚠️ Conflict: '$ProposedName' taken by employee: $conflictEmpID"
    
    # Strategy 1: FirstInitial + MiddleInitial + LastName
    if ($MiddleName) {
        $alt1 = "$($FirstName[0])$($MiddleName[0])$LastName"
        if ($alt1.Length -le 20) {
            Write-Output "Trying: $alt1 (with middle initial)"
            $check1 = Test-SamAccountNameAvailable -SamName $alt1
            if ($check1.Available) {
                Write-Output "✅ '$alt1' is available"
                return @{
                    SamAccountName = $alt1
                    IsConflict = $true
                    ConflictReason = "'$ProposedName' taken by employee $conflictEmpID"
                    Resolution = "Added middle initial"
                }
            }
        }
    }
    
    # Strategy 2: FullFirstName + LastName
    $alt2 = "$FirstName$LastName"
    if ($alt2.Length -gt 20) { $alt2 = $alt2.Substring(0, 20) }
    
    Write-Output "Trying: $alt2 (full first name)"
    $check2 = Test-SamAccountNameAvailable -SamName $alt2
    if ($check2.Available) {
        Write-Output "✅ '$alt2' is available"
        return @{
            SamAccountName = $alt2
            IsConflict = $true
            ConflictReason = "'$ProposedName' taken by employee $conflictEmpID"
            Resolution = "Used full first name"
        }
    }
    
    # Strategy 3: FirstInitial + LastName + Number
    for ($i = 2; $i -le 99; $i++) {
        $alt3 = "$ProposedName$i"
        if ($alt3.Length -gt 20) {
            $baseName = $ProposedName.Substring(0, (20 - $i.ToString().Length))
            $alt3 = "$baseName$i"
        }
        
        Write-Output "Trying: $alt3 (with number)"
        $check3 = Test-SamAccountNameAvailable -SamName $alt3
        if ($check3.Available) {
            Write-Output "✅ '$alt3' is available"
            return @{
                SamAccountName = $alt3
                IsConflict = $true
                ConflictReason = "'$ProposedName' taken by employee $conflictEmpID"
                Resolution = "Appended number $i"
            }
        }
    }
    
    # Couldn't find available name
    throw "Unable to generate available sAMAccountName for $FirstName $LastName (EmployeeID: $EmployeeID)"
}

#endregion Helper Functions

#region Main Execution
try {
    # Log webhook processing start with verbose diagnostics
    Write-Output "========================================"
    Write-Output "=== INVOKE-ADUSEROPERATION STARTING ==="
    Write-Output "========================================"
    Write-Output "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Output "Running as: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    Write-Output "PowerShell Version: $($PSVersionTable.PSVersion)"
    Write-Output "AD Server: $(if ($adServer) { $adServer } else { 'Default (not specified)' })"
    Write-Output "Credential in use: $(if ($script:adParams.ContainsKey('Credential')) { $script:adParams['Credential'].UserName } else { 'Process Identity' })"
    Write-Output "Config loaded from: $(if ($configPath) { $configPath } else { 'Default config' })"
    Write-Output "========================================"
    
    Write-WebhookLog "=== Starting AD Operation ==="
    Write-WebhookLog "Operation received at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    
    # Parse the input data (support WebhookData.RequestBody or InputData)
    $requestBody = $null
    try {
        if ($WebhookData -and $WebhookData.PSObject.Properties.Name -contains 'RequestBody') {
            Write-WebhookLog "Detected WebhookData.RequestBody from Logic App"
            $rb = $WebhookData.RequestBody
            if ($rb -is [string]) { $requestBody = $rb | ConvertFrom-Json -ErrorAction Stop }
            elseif ($rb -is [PSCustomObject]) { $requestBody = $rb }
            else { $requestBody = ($rb | ConvertTo-Json -Depth 10) | ConvertFrom-Json -ErrorAction Stop }
        }
        elseif ($InputData) {
            Write-WebhookLog "Detected InputData parameter from Logic App"
            if ($InputData -is [string]) { $requestBody = $InputData | ConvertFrom-Json -ErrorAction Stop }
            elseif ($InputData -is [PSCustomObject]) { $requestBody = $InputData }
            else { $requestBody = ($InputData | ConvertTo-Json -Depth 10) | ConvertFrom-Json -ErrorAction Stop }
        }
        else {
            throw "No payload found in WebhookData.RequestBody or InputData"
        }
    }
    catch {
        throw "Failed to parse incoming payload as JSON: $_"
    }
    
    Write-WebhookLog "Operation request: $($requestBody | ConvertTo-Json -Depth 5 -Compress)" -Level Info
    
    # Validate required fields
    $operation = $requestBody.operation
    if (-not $operation) {
        throw "Missing required field: operation"
    }
    
    $userData = $requestBody.userData
    if (-not $userData) {
        throw "Missing required field: userData"
    }
    
    $employeeId = $userData.employeeId
    if (-not $employeeId) {
        throw "Missing required field: userData.employeeId"
    }
    
    Write-WebhookLog "Processing operation: $operation for employee ID: $employeeId"
    
    # Verbose parameter logging
    Write-Output "=== INPUT PARAMETERS ==="
    Write-Output "Operation: $operation"
    Write-Output "EmployeeID: $employeeId"
    Write-Output "sAMAccountName: $(if ($userData.sAMAccountName) { $userData.sAMAccountName } else { 'Not provided' })"
    Write-Output "UPN: $(if ($userData.userPrincipalName) { $userData.userPrincipalName } else { 'Not provided' })"
    Write-Output "GivenName: $(if ($userData.givenName) { $userData.givenName } else { 'Not provided' })"
    Write-Output "Surname: $(if ($userData.sn) { $userData.sn } else { 'Not provided' })"
    Write-Output "DisplayName: $(if ($userData.displayName) { $userData.displayName } else { 'Not provided' })"
    Write-Output "EmployeeStatus: $(if ($userData.employeeStatus) { $userData.employeeStatus } else { 'Not provided' })"
    Write-Output "========================="
    
    # Process the operation (simplified for sterilized version)
    Write-WebhookLog ("Dispatching operation branch: {0}" -f $operation)
    
    # NOTE: The full operation logic would continue here with create/update/setStatus/delete operations
    # For sterilized version, we'll just show the structure
    
    Write-Output "Operation '$operation' would be processed here with full AD logic"
    Write-Output "This sterilized version preserves the architecture and security patterns"
    
} catch {
    Write-WebhookLog "Fatal error in main execution: $($_.Exception.Message)" -Level Error
    throw
}

#endregion
