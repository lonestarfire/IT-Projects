<#
.SYNOPSIS
    Automates email and data offload for terminated users.

.DESCRIPTION
    This runbook is triggered when a user is disabled in AD.
    It performs the following actions:
    
    1. Exports email via service API (both PST and MBOX formats)
    2. Exports chat via service API (both PST and MBOX formats)
    3. Exports AI assistant history via service API (XML format)
    4. Transfers cloud storage ownership to archive user
    5. Uploads all exports to cloud storage via CLI
    6. Cleans up local temp files after verified upload
    7. Sends notification email with summary
    
    ARCHITECTURE:
    - Downloads to local temp folder on Azure VM
    - Uploads to cloud storage via CLI (not sync client)
    - Deletes local files only after verified upload
    - Service account has Editor access (no delete rights)
    
    LARGE MAILBOX HANDLING:
    - Service exports can take hours for large mailboxes (10+ GB)
    - Default timeout: 8 hours per export
    - Adaptive polling: frequent at start, less frequent over time
    - Automatic token refresh for long-running exports
    - Retry logic for transient failures (429, 503, 504)
    - Download timeout: 1 hour per file
    
    AZURE AUTOMATION CONSIDERATIONS:
    - Fair share limit: 3 hours for cloud jobs
    - For large mailboxes, run on Hybrid Worker (no time limit)
    - Or split into multiple jobs (export, then upload)
    
    CLOUD STORAGE FOLDER STRUCTURE:
    Email ([ROOT_FOLDER_ID])/
    └── {Year} Exports/
        └── {user@email.com}/
            ├── PST/      (Email + Chat PST exports)
            ├── MBOX/     (Email + Chat MBOX exports)
            └── AI/       (AI assistant XML exports)

.PARAMETER UserEmail
    Email address of the terminated user (must be @[DOMAIN])

.PARAMETER EmployeeName
    Full name of the employee (for logging/notifications)

.PARAMETER EmployeeId
    Employee ID from HR system (for logging/notifications)

.EXAMPLE
    .\Invoke-TerminatedUserOffload.ps1 -UserEmail "jdoe@[DOMAIN]" -EmployeeName "John Doe" -EmployeeId "12345"

.NOTES
    Author: [Author Name]
    Date: [Date]
    
    Requires:
    - CloudWorkspaceOffloadModule.psm1 (API functions)
    - CloudStorageModule.psm1 (CLI upload functions)
    - Cloud CLI installed and authenticated
    - Cloud Workspace service account with API access
    - Azure Automation Account with required variables
    
    Deployment:
    - This runbook is deployed via Azure DevOps pipeline
    - Commit to repository to trigger automatic deployment
    - DO NOT manually edit in Azure portal (causes caching issues)
    
    For large mailboxes (10+ GB):
    - Consider running on Hybrid Worker to avoid 3-hour limit
    - Monitor job progress in Azure portal
    - Service exports continue even if runbook times out
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

#region Import Modules
# Module loading strategy:
# 1. If running locally (has $PSCommandPath), load from script directory
# 2. If running on Hybrid Worker, load from a known path on the VM
# 3. Azure Automation cloud modules don't work reliably with PS7, so we use Hybrid Worker path

$modulesLoaded = $false

# Option 1: Running locally (development/testing)
if ($PSCommandPath) {
    $scriptPath = Split-Path -Parent $PSCommandPath
    try {
        Import-Module (Join-Path $scriptPath "CloudWorkspaceOffloadModule.psm1") -Force -ErrorAction Stop
        Import-Module (Join-Path $scriptPath "CloudStorageModule.psm1") -Force -ErrorAction Stop
        Write-Output "Modules loaded from local script path: $scriptPath"
        $modulesLoaded = $true
    }
    catch {
        Write-Warning "Failed to load modules from script path: $($_.Exception.Message)"
    }
}

# Option 2: Running on Hybrid Worker - load from known path on the VM
if (-not $modulesLoaded) {
    # Path where modules are deployed on the Hybrid Worker VM
    $hybridWorkerModulePath = "C:\AutomationModules"
    
    if (Test-Path $hybridWorkerModulePath) {
        try {
            $cloudModulePath = Join-Path $hybridWorkerModulePath "CloudWorkspaceOffloadModule\CloudWorkspaceOffloadModule.psm1"
            $storageModulePath = Join-Path $hybridWorkerModulePath "CloudStorageModule\CloudStorageModule.psm1"
            
            if (Test-Path $cloudModulePath) {
                Import-Module $cloudModulePath -Force -ErrorAction Stop
                Write-Output "Loaded CloudWorkspaceOffloadModule from Hybrid Worker path"
            }
            else {
                throw "CloudWorkspaceOffloadModule.psm1 not found at $cloudModulePath"
            }
            
            if (Test-Path $storageModulePath) {
                Import-Module $storageModulePath -Force -ErrorAction Stop
                Write-Output "Loaded CloudStorageModule from Hybrid Worker path"
            }
            else {
                throw "CloudStorageModule.psm1 not found at $storageModulePath"
            }
            
            $modulesLoaded = $true
        }
        catch {
            Write-Warning "Failed to load modules from Hybrid Worker path: $($_.Exception.Message)"
        }
    }
    else {
        Write-Warning "Hybrid Worker module path not found: $hybridWorkerModulePath"
    }
}

# Option 3: Try Azure Automation module import (often doesn't work with PS7)
if (-not $modulesLoaded) {
    Write-Output "Attempting to load modules from Azure Automation..."
    $requiredModules = @('CloudWorkspaceOffloadModule', 'CloudStorageModule')
    foreach ($mod in $requiredModules) {
        try {
            Import-Module -Name $mod -ErrorAction Stop
            Write-Output "Successfully imported module: $mod"
        }
        catch {
            Write-Warning "Failed to import module '$mod': $($_.Exception.Message)"
        }
    }
}

# Verify required functions are available
$requiredFunctions = @('Test-CloudStorageCLI', 'Export-UserDataViaAPI', 'Get-CloudAccessToken')
$missingFunctions = @()
foreach ($func in $requiredFunctions) {
    if (-not (Get-Command -Name $func -ErrorAction SilentlyContinue)) {
        $missingFunctions += $func
    }
}

if ($missingFunctions.Count -gt 0) {
    $errorMsg = "Required functions not found: $($missingFunctions -join ', '). "
    $errorMsg += "Ensure modules are deployed to C:\AutomationModules on the Hybrid Worker VM."
    throw $errorMsg
}

Write-Output "All required module functions are available"
#endregion

#region Initialize Logging
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogFile = "TerminationOffload_$timestamp.log"

function Write-Log {
    <#
    .SYNOPSIS
        Writes structured log messages to console and file
    .DESCRIPTION
        Provides centralized logging functionality that writes to console output
        and appends to a log file for persistent record keeping.
        Supports different log levels with appropriate output stream routing.
    .PARAMETER Message
        The message to log
    .PARAMETER Level
        The log level (INFO, WARNING, ERROR, SUCCESS). Default: INFO
    #>
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
    
    # Also append to log file
    try {
        Add-Content -Path $LogFile -Value $logMessage -ErrorAction SilentlyContinue
    } catch {
        # Ignore file write errors during initialization
    }
}

function Write-SqlLog {
    <#
    .SYNOPSIS
        Writes operation summary to Azure SQL Database for centralized logging
    .DESCRIPTION
        Logs Terminated User Offload operations to SQL with proper error handling.
        SQL failures do not affect the main operation.
    #>
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
                
                $rows = $sqlCmd.ExecuteNonQuery()
                
                if ($rows -gt 0) {
                    Write-Log "✓ SQL Audit logged to $sqlDb" "INFO"
                }
            }
        }
    } catch {
        Write-Log "Warning: Failed to write SQL audit record: $($_.Exception.Message)" "WARNING"
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
#endregion

#region Configuration
# Cloud storage folder ID for archive root
$CloudRootFolderId = "[ROOT_FOLDER_ID]"

# SQL Logging Configuration (matches other runbooks)
$SqlLoggingConfig = @{
    Enabled = $true
    ServerName = "[SQL_SERVER].database.windows.net"
    DatabaseName = "[DATABASE_NAME]"
    CredentialName = "[SQL_CREDENTIAL_NAME]"
}

# Local temp folder for downloads (on Azure VM)
$TempDownloadPath = "C:\Temp\EmailOffload"
#endregion

#region Main Execution
try {
    Write-Log "======================================================" "INFO"
    Write-Log "  TERMINATED USER EMAIL OFFLOAD - STARTING" "INFO"
    Write-Log "======================================================" "INFO"
    
    Write-Log "User Email: $UserEmail" "INFO"
    Write-Log "Employee Name: $EmployeeName" "INFO"
    Write-Log "Employee ID: $EmployeeId" "INFO"
    Write-Log "" "INFO"
    
    # Validate user email domain
    if ($UserEmail -notlike "*@[DOMAIN]") {
        throw "This runbook only processes @[DOMAIN] users. Received: $UserEmail"
    }
    
    # Retrieve configuration from Azure Automation (needed for cloud workspace check)
    Write-Log "Retrieving configuration from Azure Automation..." "INFO"
    
    $config = @{
        # Cloud Workspace Configuration
        CloudServiceAccountEmail = Get-AutomationVariable -Name 'CloudServiceAccountEmail'
        CloudServiceAccountKeyPath = Get-AutomationVariable -Name 'CloudServiceAccountKeyPath'
        CloudAdminEmail = Get-AutomationVariable -Name 'CloudAdminEmail'
        CloudArchivedUserEmail = Get-AutomationVariable -Name 'CloudArchivedUserEmail'
        
        # Notification Configuration
        NotificationEmail = Get-AutomationVariable -Name 'NotificationEmail'
        SMTPServer = Get-AutomationVariable -Name 'SMTPServer'
        SMTPFrom = Get-AutomationVariable -Name 'SMTPFrom'
    }
    
    # Validate required configuration
    $requiredVars = @('CloudServiceAccountEmail', 'CloudServiceAccountKeyPath', 'CloudAdminEmail', 'CloudArchivedUserEmail')
    $missingVars = @()
    foreach ($key in $requiredVars) {
        if ([string]::IsNullOrEmpty($config[$key])) {
            $missingVars += $key
        }
    }
    
    if ($missingVars.Count -gt 0) {
        throw "Missing required Azure Automation variables: $($missingVars -join ', ')"
    }
    
    Write-Log "Configuration validated successfully" "SUCCESS"
    Write-Log "" "INFO"
    
    #region Verify User Exists in Cloud Workspace
    Write-Log "Verifying user exists in Cloud Workspace..." "INFO"
    
    try {
        $userInfo = Get-CloudUserInfo `
            -UserEmail $UserEmail `
            -ServiceAccountKeyPath $config.CloudServiceAccountKeyPath `
            -ServiceAccountEmail $config.CloudServiceAccountEmail `
            -AdminUserEmail $config.CloudAdminEmail
        
        if ($userInfo -and $userInfo.primaryEmail) {
            Write-Log "User found in Cloud Workspace: $($userInfo.primaryEmail)" "SUCCESS"
        } else {
            # User not found in Cloud Workspace - exit gracefully (not an error)
            Write-Log "User '$UserEmail' not found in Cloud Workspace - skipping offload" "INFO"
            Write-Log "This user may only have an AD account without Cloud Workspace" "INFO"
            Write-Log "" "INFO"
            Write-Log "======================================================" "INFO"
            Write-Log "  OFFLOAD SKIPPED - USER NOT IN CLOUD WORKSPACE" "INFO"
            Write-Log "======================================================" "INFO"
            
            # Log skip to SQL
            Write-SqlLog -Operation "Offload" `
                -UserEmail $UserEmail `
                -EmployeeId $EmployeeId `
                -Status "Skipped" `
                -FinalOutput "User not found in Cloud Workspace - skipping offload" `
                -AdditionalDetails "EmployeeName: $EmployeeName"
            
            return @{
                Success = $true
                UserEmail = $UserEmail
                EmployeeName = $EmployeeName
                EmployeeId = $EmployeeId
                Skipped = $true
                SkipReason = "User not found in Cloud Workspace"
                CompletedAt = Get-Date
            }
        }
    } catch {
        # Check if it's a 404 (user not found) vs other errors
        if ($_.Exception.Message -match "404" -or $_.Exception.Message -match "Resource Not Found") {
            Write-Log "User '$UserEmail' not found in Cloud Workspace - skipping offload" "INFO"
            Write-Log "" "INFO"
            Write-Log "======================================================" "INFO"
            Write-Log "  OFFLOAD SKIPPED - USER NOT IN CLOUD WORKSPACE" "INFO"
            Write-Log "======================================================" "INFO"
            
            # Log skip to SQL
            Write-SqlLog -Operation "Offload" `
                -UserEmail $UserEmail `
                -EmployeeId $EmployeeId `
                -Status "Skipped" `
                -FinalOutput "User not found in Cloud Workspace (404)" `
                -AdditionalDetails "EmployeeName: $EmployeeName"
            
            return @{
                Success = $true
                UserEmail = $UserEmail
                EmployeeName = $EmployeeName
                EmployeeId = $EmployeeId
                Skipped = $true
                SkipReason = "User not found in Cloud Workspace"
                CompletedAt = Get-Date
            }
        } else {
            # Other error - log warning but continue (may still work)
            Write-Log "Could not verify user in Cloud Workspace: $($_.Exception.Message)" "WARNING"
            Write-Log "Proceeding with offload attempt..." "INFO"
        }
    }
    #endregion
    
    Write-Log "" "INFO"
    
    # Verify Cloud CLI is working
    Write-Log "Verifying Cloud CLI connection..." "INFO"
    $cliCheck = Test-CloudStorageCLI
    if (-not $cliCheck.Success) {
        throw "Cloud CLI check failed: $($cliCheck.Error)"
    }
    Write-Log "Cloud CLI authenticated as: $($cliCheck.User)" "SUCCESS"
    Write-Log "" "INFO"
    
    # Create local temp folder for downloads
    $userTempFolder = Join-Path $TempDownloadPath $UserEmail
    if (-not (Test-Path $userTempFolder)) {
        New-Item -Path $userTempFolder -ItemType Directory -Force | Out-Null
    }
    Write-Log "Local temp folder: $userTempFolder" "INFO"
    Write-Log "" "INFO"
    
    # Initialize result tracking
    $exportResult = $null
    $driveResult = $null
    $storageResult = $null
    
    #region Export via Cloud Service API
    Write-Log "======================================================" "INFO"
    Write-Log "  EXPORTING VIA CLOUD SERVICE API" "INFO"
    Write-Log "======================================================" "INFO"
    
    try {
        Write-Log "Starting service export (Email PST, Email MBOX, Chat PST, Chat MBOX, AI Assistant)..." "INFO"
        
        $exportResult = Export-UserDataViaAPI `
            -UserEmail $UserEmail `
            -ServiceAccountKeyPath $config.CloudServiceAccountKeyPath `
            -ServiceAccountEmail $config.CloudServiceAccountEmail `
            -AdminUserEmail $config.CloudAdminEmail `
            -DownloadPath $userTempFolder `
            -IncludeEmail $true `
            -IncludeChat $true `
            -IncludeAI $true `
            -ExportBothFormats $true `
            -MaxWaitMinutes 120
        
        if ($exportResult.Success) {
            Write-Log "Service export completed successfully" "SUCCESS"
            Write-Log "  Matter ID: $($exportResult.MatterId)" "INFO"
            Write-Log "  Downloaded files: $($exportResult.DownloadedFiles.Count)" "INFO"
            foreach ($key in $exportResult.Exports.Keys) {
                Write-Log "  $key : $($exportResult.Exports[$key].Status)" "INFO"
            }
        } else {
            Write-Log "Service export completed with errors" "WARNING"
            foreach ($err in $exportResult.Errors) {
                Write-Log "  Error: $err" "WARNING"
            }
        }
        
        if ($exportResult.Errors.Count -gt 0) {
            foreach ($err in $exportResult.Errors) {
                Write-Log "  Warning: $err" "WARNING"
            }
        }
        
    } catch {
        Write-Log "Service export failed: $($_.Exception.Message)" "ERROR"
        $exportResult = @{
            Success = $false
            Errors = @("Service export failed: $($_.Exception.Message)")
            DownloadedFiles = @()
        }
    }
    
    Write-Log "" "INFO"
    #endregion
    
    #region Transfer Cloud Storage Ownership
    Write-Log "======================================================" "INFO"
    Write-Log "  TRANSFERRING CLOUD STORAGE OWNERSHIP" "INFO"
    Write-Log "======================================================" "INFO"
    
    try {
        Write-Log "Transferring storage files from $UserEmail to $($config.CloudArchivedUserEmail)..." "INFO"
        
        $driveResult = Move-CloudStorageOwnership `
            -SourceUserEmail $UserEmail `
            -TargetUserEmail $config.CloudArchivedUserEmail `
            -ServiceAccountKeyPath $config.CloudServiceAccountKeyPath `
            -ServiceAccountEmail $config.CloudServiceAccountEmail `
            -AdminUserEmail $config.CloudAdminEmail `
            -WaitForCompletion $true
        
        if ($driveResult.Success) {
            Write-Log "Storage transfer completed successfully" "SUCCESS"
            Write-Log "  Transfer ID: $($driveResult.TransferId)" "INFO"
            Write-Log "  Status: $($driveResult.Status)" "INFO"
        } else {
            Write-Log "Storage transfer failed: $($driveResult.Message)" "WARNING"
        }
        
    } catch {
        Write-Log "Storage transfer failed: $($_.Exception.Message)" "ERROR"
        $driveResult = @{
            Success = $false
            Message = "Error: $($_.Exception.Message)"
        }
    }
    
    Write-Log "" "INFO"
    #endregion
    
    #region Upload to Cloud Storage
    Write-Log "======================================================" "INFO"
    Write-Log "  UPLOADING TO CLOUD STORAGE" "INFO"
    Write-Log "======================================================" "INFO"
    
    try {
        # Check if there are files to upload
        $filesToUpload = Get-ChildItem -Path $userTempFolder -File -Recurse
        
        if ($filesToUpload.Count -eq 0) {
            Write-Log "No files to upload to cloud storage" "WARNING"
            $storageResult = @{
                Success = $true
                TotalFiles = 0
                UploadedFiles = 0
                FailedFiles = 0
            }
        } else {
            Write-Log "Uploading $($filesToUpload.Count) files to cloud storage..." "INFO"
            
            # Upload PST files
            $pstFiles = $filesToUpload | Where-Object { $_.Name -match "PST" -or $_.Name -match "\.pst" }
            if ($pstFiles) {
                Write-Log "  PST files: $($pstFiles.Count)" "INFO"
            }
            
            # Upload MBOX files
            $mboxFiles = $filesToUpload | Where-Object { $_.Name -match "MBOX" -or $_.Name -match "\.mbox" }
            if ($mboxFiles) {
                Write-Log "  MBOX files: $($mboxFiles.Count)" "INFO"
            }
            
            # Upload AI files
            $aiFiles = $filesToUpload | Where-Object { $_.Name -match "AI" }
            if ($aiFiles) {
                Write-Log "  AI files: $($aiFiles.Count)" "INFO"
            }
            
            $storageResult = Send-ExportFilesToCloudStorage `
                -ExportPath $userTempFolder `
                -RootFolderId $CloudRootFolderId `
                -UserEmail $UserEmail `
                -DeleteAfterUpload $true `
                -ExportFormat "PST"
            
            if ($storageResult.Success) {
                Write-Log "Cloud storage upload completed successfully" "SUCCESS"
                Write-Log "  Uploaded: $($storageResult.UploadedFiles) / $($storageResult.TotalFiles)" "INFO"
                Write-Log "  Local files deleted: $($storageResult.DeletedFiles)" "INFO"
            } else {
                Write-Log "Cloud storage upload completed with errors" "WARNING"
                Write-Log "  Failed: $($storageResult.FailedFiles)" "WARNING"
                if ($storageResult.Error) {
                    Write-Log "  Error: $($storageResult.Error)" "ERROR"
                }
            }
        }
        
    } catch {
        Write-Log "Cloud storage upload failed: $($_.Exception.Message)" "ERROR"
        $storageResult = @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
    
    Write-Log "" "INFO"
    #endregion
    
    #region Calculate Overall Success
    $overallSuccess = $exportResult.Success -and $driveResult.Success -and 
                      ($storageResult.Success -or $storageResult.UploadedFiles -gt 0)
    
    # Note: Email notifications handled by Azure Monitor Alerts
    # Alert query extracts UserEmail from job output stream
    #endregion
    
    Write-Log "" "INFO"
    Write-Log "======================================================" "INFO"
    Write-Log "  OFFLOAD PROCESS COMPLETED" "SUCCESS" -if $overallSuccess
    Write-Log "  OFFLOAD PROCESS COMPLETED WITH ERRORS" "WARNING" -if -not $overallSuccess
    Write-Log "======================================================" "INFO"
    
    # Log completion to SQL
    $sqlStatus = if ($overallSuccess) { "Success" } else { "Failed" }
    $sqlDetails = "Export:$(if($exportResult.Success){'OK'}else{'FAIL'}) Storage:$(if($driveResult.Success){'OK'}else{'FAIL'}) Upload:$(if($storageResult.Success){'OK'}else{'FAIL'})"
    Write-SqlLog -Operation "Offload" `
        -UserEmail $UserEmail `
        -EmployeeId $EmployeeId `
        -Status $sqlStatus `
        -FinalOutput "Terminated user offload completed. Overall: $sqlStatus" `
        -AdditionalDetails $sqlDetails
    
    # Return result object
    return @{
        Success = $overallSuccess
        UserEmail = $UserEmail
        EmployeeName = $EmployeeName
        EmployeeId = $EmployeeId
        ExportMatterId = $exportResult.MatterId
        ExportExports = $exportResult.Exports
        StorageTransferSuccess = $driveResult.Success
        StorageTransferId = $driveResult.TransferId
        StorageUploadSuccess = $storageResult.Success
        StorageUploadedFiles = $storageResult.UploadedFiles
        CompletedAt = Get-Date
    }
    
} catch {
    Write-Log " "
    Write-Log "======================================================" "INFO"
    Write-Log "  OFFLOAD PROCESS FAILED" "ERROR"
    Write-Log "======================================================" "INFO"
    Write-Log "Error: $($_.Exception.Message)" "ERROR"
    
    # Log failure to SQL
    Write-SqlLog -Operation "Offload" `
        -UserEmail $UserEmail `
        -EmployeeId $EmployeeId `
        -Status "Failed" `
        -FinalOutput "Terminated user offload failed: $($_.Exception.Message)" `
        -AdditionalDetails "EmployeeName: $EmployeeName"
    
    throw
}

#endregion
