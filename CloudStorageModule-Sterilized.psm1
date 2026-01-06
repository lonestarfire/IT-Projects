<#
.SYNOPSIS
    Helper module for Cloud Storage CLI operations

.DESCRIPTION
    Provides functions to interact with Cloud Storage via the CLI
    for uploading terminated user data exports.
    
    PREREQUISITES:
    - Cloud CLI must be installed: https://github.com/[CLOUD_PROVIDER]/[CLI_NAME]
    - Cloud CLI must be authenticated: [CLI_NAME] login
    
    PERMISSIONS:
    The service account has Editor access (principle of least privilege):
    - Can create folders
    - Can upload files
    - CANNOT delete or move files (by design)
    
    FOLDER STRUCTURE:
    Email ([ROOT_FOLDER_ID])/
    └── {Year} Exports/           (e.g., "2025 Exports")
        └── {user@email.com}/     (e.g., "user@[DOMAIN]")
            ├── PST/              (Email PST + Chat PST)
            ├── MBOX/             (Email MBOX + Chat MBOX)
            └── AI/               (AI assistant XML exports)
#>

#region Configuration

# Cloud storage folder ID for the Email Archive root folder
$script:StorageArchiveRootFolderId = "[ROOT_FOLDER_ID]"

# Debug log file path
$script:StorageDebugLogPath = "C:\Temp\StorageCLIModule_Debug.log"

#endregion

#region Helper Functions

function Write-StorageDebug {
    <#
    .SYNOPSIS
        Writes debug messages to both console and a local log file
    .DESCRIPTION
        Provides centralized debug logging for Cloud Storage operations.
        Writes to console output and maintains a persistent log file for troubleshooting.
    .PARAMETER Message
        The message to log
    #>
    param([string]$Message)
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    
    # Write to console
    Write-Output $logEntry
    
    # Append to log file
    try {
        $logDir = Split-Path $script:StorageDebugLogPath -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        Add-Content -Path $script:StorageDebugLogPath -Value $logEntry -ErrorAction SilentlyContinue
    }
    catch {
        # Silently continue if logging fails
    }
}

function Test-CloudStorageCLI {
    <#
    .SYNOPSIS
        Verifies Cloud Storage CLI is installed and authenticated
    .DESCRIPTION
        Tests Cloud Storage CLI installation and authentication status.
        Returns detailed information about CLI version and authenticated user.
    .RETURNS
        Hashtable with success status, version, and authenticated user information
    #>
    [CmdletBinding()]
    param()
    
    try {
        $result = & [CLI_NAME] --version 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Cloud Storage CLI not found or not working"
        }
        
        # Test authentication by getting current user
        $userJson = & [CLI_NAME] users:get --json 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Cloud Storage CLI not authenticated. Run '[CLI_NAME] login' first."
        }
        
        $user = $userJson | ConvertFrom-Json
        Write-Verbose "Cloud Storage CLI authenticated as: $($user.login)"
        
        return @{
            Success = $true
            Version = $result
            User = $user.login
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-StorageFolderId {
    <#
    .SYNOPSIS
        Gets or creates a folder in Cloud Storage
    .DESCRIPTION
        Searches for an existing folder by name and parent folder ID.
        If not found, creates a new folder with the specified name.
        Returns the folder ID for use in subsequent operations.
    .PARAMETER FolderName
        The name of the folder to find or create
    .PARAMETER ParentFolderId
        The parent folder ID. Defaults to root archive folder
    .RETURNS
        The folder ID of the existing or newly created folder
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FolderName,
        
        [Parameter(Mandatory = $false)]
        [string]$ParentFolderId = $script:StorageArchiveRootFolderId
    )
    
    try {
        Write-StorageDebug "Looking for folder: $FolderName"
        
        # Try to find existing folder
        $searchJson = & [CLI_NAME] folders:search --parent-id $ParentFolderId --name "$FolderName" --json 2>&1
        if ($LASTEXITCODE -eq 0) {
            $searchResult = $searchJson | ConvertFrom-Json
            if ($searchResult.total_count -gt 0) {
                $folderId = $searchResult.entries[0].id
                Write-StorageDebug "Found existing folder: $FolderName (ID: $folderId)"
                return $folderId
            }
        }
        
        # Create new folder if not found
        Write-StorageDebug "Creating new folder: $FolderName"
        $createJson = & [CLI_NAME] folders:create --parent-id $ParentFolderId --name "$FolderName" --json 2>&1
        if ($LASTEXITCODE -eq 0) {
            $createResult = $createJson | ConvertFrom-Json
            $folderId = $createResult.id
            Write-StorageDebug "Created folder: $FolderName (ID: $folderId)"
            return $folderId
        } else {
            throw "Failed to create folder: $FolderName"
        }
        
    } catch {
        Write-StorageDebug "Error getting/creating folder '$FolderName': $($_.Exception.Message)"
        throw
    }
}

function Send-ExportFilesToCloudStorage {
    <#
    .SYNOPSIS
        Uploads exported files to Cloud Storage with proper folder structure
    .DESCRIPTION
        Organizes and uploads exported files to Cloud Storage with a standardized
        folder hierarchy (Year/User/Format). Handles file classification, upload
        progress tracking, and optional local file cleanup.
    .PARAMETER ExportPath
        Local path containing files to upload
    .PARAMETER RootFolderId
        Root folder ID in Cloud Storage
    .PARAMETER UserEmail
        User email for folder naming
    .PARAMETER DeleteAfterUpload
        Whether to delete local files after successful upload
    .PARAMETER ExportFormat
        Default export format for folder classification
    .RETURNS
        Hashtable with upload results and statistics
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExportPath,
        
        [Parameter(Mandatory = $true)]
        [string]$RootFolderId,
        
        [Parameter(Mandatory = $true)]
        [string]$UserEmail,
        
        [Parameter(Mandatory = $false)]
        [bool]$DeleteAfterUpload = $true,
        
        [Parameter(Mandatory = $false)]
        [string]$ExportFormat = "PST"
    )
    
    try {
        Write-StorageDebug "Starting upload to Cloud Storage"
        Write-StorageDebug "Export path: $ExportPath"
        Write-StorageDebug "User email: $UserEmail"
        Write-StorageDebug "Delete after upload: $DeleteAfterUpload"
        
        # Get all files to upload
        $filesToUpload = Get-ChildItem -Path $ExportPath -File -Recurse
        if ($filesToUpload.Count -eq 0) {
            Write-StorageDebug "No files found to upload"
            return @{
                Success = $true
                TotalFiles = 0
                UploadedFiles = 0
                FailedFiles = 0
                DeletedFiles = 0
            }
        }
        
        Write-StorageDebug "Found $($filesToUpload.Count) files to upload"
        
        # Create folder structure
        $currentYear = Get-Date -Format "yyyy"
        $yearFolderName = "$currentYear Exports"
        $userFolderName = $UserEmail
        
        $yearFolderId = Get-StorageFolderId -FolderName $yearFolderName -ParentFolderId $RootFolderId
        $userFolderId = Get-StorageFolderId -FolderName $userFolderName -ParentFolderId $yearFolderId
        
        # Create format-specific folders
        $formatFolders = @{}
        $formatTypes = @("PST", "MBOX", "AI")
        
        foreach ($format in $formatTypes) {
            $formatFolderId = Get-StorageFolderId -FolderName $format -ParentFolderId $userFolderId
            $formatFolders[$format] = $formatFolderId
        }
        
        # Upload files
        $uploadedCount = 0
        $failedCount = 0
        $deletedCount = 0
        
        foreach ($file in $filesToUpload) {
            try {
                # Determine target folder based on file name
                $targetFolderId = $null
                $fileName = $file.Name
                
                if ($fileName -match "PST|\.pst") {
                    $targetFolderId = $formatFolders["PST"]
                } elseif ($fileName -match "MBOX|\.mbox") {
                    $targetFolderId = $formatFolders["MBOX"]
                } elseif ($fileName -match "AI|Gemini") {
                    $targetFolderId = $formatFolders["AI"]
                } else {
                    # Default to PST folder
                    $targetFolderId = $formatFolders["PST"]
                }
                
                Write-StorageDebug "Uploading: $($file.Name) -> folder ID: $targetFolderId"
                
                # Upload file using CLI
                $uploadJson = & [CLI_NAME] files:upload --parent-id $targetFolderId --file "$($file.FullName)" --json 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $uploadResult = $uploadJson | ConvertFrom-Json
                    $uploadedCount++
                    Write-StorageDebug "Successfully uploaded: $($file.Name) (ID: $($uploadResult.id))"
                    
                    # Delete local file if requested
                    if ($DeleteAfterUpload) {
                        Remove-Item $file.FullName -Force
                        $deletedCount++
                        Write-StorageDebug "Deleted local file: $($file.Name)"
                    }
                    
                } else {
                    $failedCount++
                    Write-StorageDebug "Failed to upload: $($file.Name)"
                }
                
            } catch {
                $failedCount++
                Write-StorageDebug "Error uploading $($file.Name): $($_.Exception.Message)"
            }
        }
        
        Write-StorageDebug "Upload completed: $uploadedCount uploaded, $failedCount failed, $deletedCount deleted"
        
        return @{
            Success = $failedCount -eq 0
            TotalFiles = $filesToUpload.Count
            UploadedFiles = $uploadedCount
            FailedFiles = $failedCount
            DeletedFiles = $deletedCount
            UserFolderId = $userFolderId
        }
        
    } catch {
        Write-StorageDebug "Upload process failed: $($_.Exception.Message)"
        return @{
            Success = $false
            Error = $_.Exception.Message
            TotalFiles = 0
            UploadedFiles = 0
            FailedFiles = 0
            DeletedFiles = 0
        }
    }
}

function Confirm-StorageUploadComplete {
    <#
    .SYNOPSIS
        Verifies that files were uploaded successfully to Cloud Storage
    .DESCRIPTION
        Lists and verifies files in a Cloud Storage folder to confirm
        successful upload completion. Provides file count and size statistics.
    .PARAMETER BoxFolderId
        The folder ID to verify (parameter name kept for compatibility)
    .RETURNS
        Hashtable with verification results and file statistics
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BoxFolderId
    )
    
    try {
        Write-StorageDebug "Verifying upload completion for folder ID: $BoxFolderId"
        
        # List files in the folder
        $listJson = & [CLI_NAME] folders:items --id $BoxFolderId --json 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to list folder contents"
        }
        
        $listResult = $listJson | ConvertFrom-Json
        $files = $listResult.entries | Where-Object { $_.type -eq "file" }
        
        $totalSize = ($files | Measure-Object -Property size -Sum).Sum
        
        Write-StorageDebug "Verification complete: $($files.Count) files, $([math]::Round($totalSize/1MB, 2)) MB total"
        
        return @{
            Success = $true
            FilesFound = $files.Count
            TotalSizeBytes = $totalSize
            Files = $files
        }
        
    } catch {
        Write-StorageDebug "Verification failed: $($_.Exception.Message)"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

#endregion
