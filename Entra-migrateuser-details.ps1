# Azure User Migration Script (Entra ID Only)
<#
.SYNOPSIS
    Migrates user attributes and permissions between accounts in Microsoft Entra ID.
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$OldUPN,

    [Parameter(Mandatory = $true)]
    [string]$NewUPN
)

# Set TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Logging function - Define this first
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Debug')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Output to console with color
    switch ($Level) {
        'Info'    { Write-Host $logMessage -ForegroundColor White }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
        'Success' { Write-Host $logMessage -ForegroundColor Green }
        'Debug'   { Write-Host $logMessage -ForegroundColor Cyan }
    }
}

# Required Graph modules
$requiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Groups",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Applications",
    "Microsoft.Graph.Users.Actions",
    "Microsoft.Graph.DirectoryObjects"
)

# Function to check if modules are already loaded
function Test-ModulesLoaded {
    $missingModules = @()
    foreach ($module in $requiredModules) {
        if (-not (Get-Module $module -ErrorAction SilentlyContinue)) {
            $missingModules += $module
        }
    }
    return $missingModules
}

# Function to install a single module
function Install-SingleModule {
    param (
        [string]$ModuleName
    )
    
    try {
        Write-Log "Installing module: $ModuleName" -Level Info
        Install-Module -Name $ModuleName -Scope CurrentUser -AllowClobber -Force -Repository PSGallery
        Write-Log "Successfully installed $ModuleName" -Level Success
    }
    catch {
        Write-Log "Failed to install $ModuleName : $_" -Level Error
        throw
    }
}

# Function to import a single module
function Import-SingleModule {
    param (
        [string]$ModuleName
    )
    
    try {
        Write-Log "Importing module: $ModuleName" -Level Info
        Import-Module -Name $ModuleName -Force -ErrorAction Stop
        Write-Log "Successfully imported $ModuleName" -Level Success
        return $true
    }
    catch {
        Write-Log "Failed to import $ModuleName : $_" -Level Error
        return $false
    }
}

# Main module installation and import function
function Initialize-GraphModules {
    try {
        # Check if modules are already loaded
        $missingModules = Test-ModulesLoaded
        if ($missingModules.Count -eq 0) {
            Write-Log "All required modules are already loaded" -Level Success
            return
        }

        Write-Log "Setting up PowerShell Gallery..." -Level Info
        if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -Force -Scope CurrentUser | Out-Null
        }
        
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        
        foreach ($module in $requiredModules) {
            if (-not (Get-Module -ListAvailable -Name $module -ErrorAction SilentlyContinue)) {
                Install-SingleModule -ModuleName $module
            }
            
            if (-not (Import-SingleModule -ModuleName $module)) {
                throw "Failed to import $module"
            }
        }
        
        Write-Log "All modules installed and imported successfully" -Level Success
    }
    catch {
        Write-Log "Error in module initialization: $_" -Level Error
        throw
    }
}

# Initialize the modules
Initialize-GraphModules

# Check and establish Microsoft Graph connection
try {
    $context = Get-MgContext
    if (-not $context) {
        Write-Log "Not connected to Microsoft Graph. Connecting..." -Level Info
        . "$PSScriptRoot\Connect-EntraGraph.ps1"
    }
    else {
        Write-Log "Already connected to Microsoft Graph as $($context.Account)" -Level Success
    }
}
catch {
    Write-Log "Error checking Microsoft Graph connection: $_" -Level Error
    Write-Log "Attempting to reconnect..." -Level Info
    . "$PSScriptRoot\Connect-EntraGraph.ps1"
}

function Test-EntraUser {
    param([string]$UPN)
    
    try {
        Get-MgUser -UserId $UPN -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Get-UserAttributes {
    param([string]$UPN)
    
    Write-Log "Collecting attributes for user $UPN..." -Level Info
    
    try {
        $userData = @{
            AdminRoles = @()
            Groups = @()
            Licenses = @()
            AzureRoles = @()
            EnterpriseApps = @()
            SourceUPN = $UPN
            TargetUPN = $NewUPN
        }

        # Get user object
        $user = Get-MgUser -UserId $UPN -ErrorAction Stop
        Write-Log "User found: $($user.DisplayName)" -Level Success

        # Get administrative role assignments
        Write-Log "`nAdministrative Roles:" -Level Info
        Write-Log "===================" -Level Info
        $directoryRoles = Get-MgUserMemberOf -UserId $UPN -All
        $adminRoles = $directoryRoles | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.directoryRole' }
        foreach ($role in $adminRoles) {
            Write-Log "- $($role.AdditionalProperties.displayName)" -Level Success
            $userData.AdminRoles += $role
        }

        # Get non-dynamic group memberships
        Write-Log "`nNon-Dynamic Group Memberships:" -Level Info
        Write-Log "==========================" -Level Info
        $groups = Get-MgUserMemberOf -UserId $UPN -All
        $nonDynamicGroups = $groups | Where-Object { 
            $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' -and
            -not ($_.AdditionalProperties.groupTypes -contains 'DynamicMembership')
        }
        foreach ($group in $nonDynamicGroups) {
            Write-Log "- $($group.AdditionalProperties.displayName)" -Level Success
            Write-Log "  ID: $($group.Id)" -Level Info
            $userData.Groups += $group
        }

        # Get assigned licenses using Get-MgUserLicenseDetail
        Write-Log "`nAssigned Licenses:" -Level Info
        Write-Log "=================" -Level Info
        $licenses = Get-UserLicensesWithRetry -UserPrincipalName $UPN
        foreach ($license in $licenses) {
            $skuPartNumber = $license.SkuPartNumber
            Write-Log "- $($license.SkuPartNumber)" -Level Success
            Write-Log "  SKU ID: $($license.SkuId)" -Level Info
            Write-Log "  SKU Part Number: $skuPartNumber" -Level Info
            $userData.Licenses += $license
        }

        # Get Azure RBAC roles
        Write-Log "`nAzure RBAC Roles:" -Level Info
        Write-Log "===================================" -Level Info
        try {
            $azureRoles = az role assignment list --assignee $UPN --include-inherited --include-groups --query "[].{roleName:roleDefinitionName, scope:scope, principalName:principalName, principalType:principalType, resourceName:resourceName}" -o json | ConvertFrom-Json
            if ($azureRoles) {
                foreach ($role in $azureRoles) {
                    Write-Log "- Role: $($role.roleName)" -Level Success
                    
                    # Extract resource type and name from scope
                    $scopeParts = $role.scope -split '/'
                    $resourceType = if ($scopeParts.Length -gt 3) { $scopeParts[-2] } else { "Subscription" }
                    $resourceName = if ($scopeParts.Length -gt 3) { $scopeParts[-1] } else { "Azure subscription" }
                    
                    Write-Log "  Resource: $resourceName" -Level Info
                    Write-Log "  Type: $resourceType" -Level Info
                    Write-Log "  Principal: $($role.principalName)" -Level Info
                    Write-Log "  Principal Type: $($role.principalType)" -Level Info
                    Write-Log "  Scope: $($role.scope)" -Level Info
                    Write-Log "" -Level Info
                    $userData.AzureRoles += $role
                }
            }
        }
        catch {
            Write-Log "Error getting Azure RBAC roles: $_" -Level Error
        }

        # Get Enterprise Application Assignments
        Write-Log "`nEnterprise Application Assignments:" -Level Info
        Write-Log "================================" -Level Info
        $appAssignments = Get-MgUserAppRoleAssignment -UserId $UPN
        foreach ($assignment in $appAssignments) {
            $app = Get-MgServicePrincipal -ServicePrincipalId $assignment.ResourceId
            Write-Log "- Application: $($app.DisplayName)" -Level Success
            if ($assignment.AppRoleId) {
                Write-Log "  Role ID: $($assignment.AppRoleId)" -Level Info
            }
            else {
                Write-Log "  Assignment Type: Default Access" -Level Info
            }
            Write-Log "  Principal ID: $($assignment.PrincipalId)" -Level Info
            $userData.EnterpriseApps += @{
                Application = $app
                Assignment = $assignment
            }
        }

        return $userData
    }
    catch {
        Write-Log "Error collecting user attributes: $_" -Level Error
        throw $_
    }
}

function Get-UserLicensesWithRetry {
    param (
        [string]$UserPrincipalName
    )
    try {
        $licenses = Get-MgUserLicenseDetail -UserId $UserPrincipalName -ErrorAction Stop
        return $licenses
    }
    catch {
        Write-Log "Could not retrieve licenses for $UserPrincipalName. Error: $($_.Exception.Message)" -Level Warning
        return @()
    }
}

function Remove-OldUser {
    param([string]$UPN, [Array]$SourceLicenses)
    
    try {
        Write-Log "Removing licenses from user $UPN..." -Level Info
        
        if ($SourceLicenses) {
            $licenseParams = @{
                AddLicenses = @() # Add an empty array for AddLicenses
                RemoveLicenses = $SourceLicenses.SkuId
            }
            Set-MgUserLicense -UserId $UPN -BodyParameter $licenseParams
        }
        
        Write-Log "Successfully removed licenses from user $UPN" -Level Success
        
        Write-Log "Removing user $UPN..." -Level Info
        Remove-MgUser -UserId $UPN
        Write-Log "Successfully removed user $UPN" -Level Success
    }
    catch {
        Write-Log "Error removing user: $_" -Level Error
        throw
    }
}

function Set-UserAttributes {
    param(
        [string]$UPN,
        [PSCustomObject]$Attributes,
        [Array]$SourceLicenses
    )
    
    Write-Log "Applying attributes to user $UPN..." -Level Info
    
    try {
        # Get the user's ID
        $userId = (Get-MgUser -UserId $UPN).Id

        # Get source user's usage location or use default
        Write-Log "Getting source user's usage location..." -Level Info
        $usageLocation = if ($Attributes.UsageLocation) { 
            $Attributes.UsageLocation 
        } else { 
            Write-Log "Could not retrieve source user's usage location, using default: US" -Level Warning
            "US" 
        }
        
        # Set usage location
        Write-Log "Setting usage location to: $usageLocation" -Level Info
        Update-MgUser -UserId $UPN -UsageLocation $usageLocation
        Write-Log "Successfully set usage location to: $usageLocation" -Level Success
        
        # Add administrative roles
        Write-Log "`nApplying administrative roles..." -Level Info
        foreach ($role in $Attributes.AdminRoles) {
            try {
                $roleId = $role.Id
                $roleName = $role.AdditionalProperties.displayName
                Write-Log "Adding role: $roleName" -Level Info
                
                # Check if user already has the role
                $userRoles = Get-MgUserMemberOf -UserId $UPN -All | Where-Object { $_.Id -eq $roleId }
                if ($userRoles) {
                    Write-Log "User already has role: $roleName. Skipping." -Level Warning
                    continue
                }
                
                $params = @{
                    "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$userId"
                }
                
                New-MgDirectoryRoleMemberByRef -DirectoryRoleId $roleId -BodyParameter $params
                Write-Log "Successfully added role: $roleName" -Level Success
            }
            catch {
                Write-Log "Failed to add role $roleName`: $_" -Level Error
            }
        }

        # Add group memberships
        Write-Log "`nApplying group memberships..." -Level Info
        $syncedGroups = @()
        $successfulGroups = @()
        $failedGroups = @()

        foreach ($group in $Attributes.Groups) {
            try {
                $groupId = $group.Id
                $groupName = $group.AdditionalProperties.displayName
                Write-Log "Processing group: $groupName" -Level Info
                
                # First try to get the group to check if it's synced
                $groupDetails = Get-MgGroup -GroupId $groupId
                if ($groupDetails.OnPremisesSyncEnabled) {
                    Write-Log "Group $groupName is synced from on-premises. Skipping direct assignment." -Level Warning
                    $syncedGroups += $groupName
                    continue
                }
                
                # Check if user is already a member of the group
                $groupMembers = Get-MgGroupMember -GroupId $groupId
                if ($groupMembers.Id -contains $userId) {
                    Write-Log "User is already a member of group: $groupName. Skipping." -Level Warning
                    $successfulGroups += $groupName
                    continue
                }
                
                $params = @{
                    "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$userId"
                }
                
                New-MgGroupMemberByRef -GroupId $groupId -BodyParameter $params
                Write-Log "Successfully added to group: $groupName" -Level Success
                $successfulGroups += $groupName
            }
            catch {
                if ($_.Exception.Message -like "*Unable to update the specified properties for on-premises mastered Directory Sync objects*") {
                    Write-Log "Group $groupName is synced from on-premises. Skipping." -Level Warning
                    $syncedGroups += $groupName
                }
                else {
                    Write-Log "Failed to add to group $groupName`: $_" -Level Error
                    $failedGroups += $groupName
                }
            }
        }

        # Group Membership Summary
        Write-Log "`nGroup Membership Migration Summary:" -Level Info
        Write-Log "================================" -Level Info
        
        if ($successfulGroups.Count -gt 0) {
            Write-Log "`nSuccessfully Added Groups:" -Level Success
            foreach ($group in $successfulGroups) {
                Write-Log "- $group" -Level Success
            }
        }
        
        if ($syncedGroups.Count -gt 0) {
            Write-Log "`nOn-Premises Synced Groups (Must be managed in Active Directory):" -Level Warning
            foreach ($group in $syncedGroups) {
                Write-Log "- $group" -Level Warning
            }
            Write-Log "`nNOTE: The above groups are synchronized from on-premises Active Directory." -Level Warning
            Write-Log "      Please ensure these group memberships are managed in your local Active Directory." -Level Warning
        }
        
        if ($failedGroups.Count -gt 0) {
            Write-Log "`nFailed Group Assignments:" -Level Error
            foreach ($group in $failedGroups) {
                Write-Log "- $group" -Level Error
            }
        }

        # Add licenses
        Write-Log "`nApplying licenses..." -Level Info
        
        # Add a delay to ensure usage location and other changes are propagated
        Write-Log "Waiting 30 seconds for changes to propagate..." -Level Info
        Start-Sleep -Seconds 30
        
        foreach ($license in $Attributes.Licenses) {
            try {
                $skuId = $license.SkuId
                $skuPartNumber = $license.SkuPartNumber
                Write-Log "Processing license: $skuPartNumber (SKU ID: $skuId)" -Level Info
                
                # Get the current license state
                $currentLicenses = Get-MgUserLicenseDetail -UserId $userId
                Write-Log "Current licenses:" -Level Info
                foreach ($cl in $currentLicenses) {
                    Write-Log "- $($cl.SkuPartNumber) ($($cl.SkuId))" -Level Info
                }
                
                if ($currentLicenses.SkuId -contains $skuId) {
                    Write-Log "License $skuPartNumber is already assigned" -Level Warning
                    continue
                }
                
                Write-Log "Preparing license assignment for $skuPartNumber" -Level Info
                $licenseParams = @{
                    AddLicenses = @(
                        @{
                            SkuId = $skuId
                            DisabledPlans = @()
                        }
                    )
                    RemoveLicenses = @()
                }
                
                Write-Log "License parameters:" -Level Info
                Write-Log ($licenseParams | ConvertTo-Json) -Level Info
                
                # Retry logic for license assignment
                $maxRetries = 3
                $retryCount = 0
                $success = $false
                
                while (-not $success -and $retryCount -lt $maxRetries) {
                    try {
                        Write-Log "Attempting license assignment (Attempt $($retryCount + 1) of $maxRetries)" -Level Info
                        Set-MgUserLicense -UserId $userId -BodyParameter $licenseParams
                        Write-Log "Successfully added license: $skuPartNumber" -Level Success
                        $success = $true
                    }
                    catch {
                        $retryCount++
                        Write-Log "License assignment error: $($_.Exception.Message)" -Level Error
                        if ($retryCount -lt $maxRetries) {
                            Write-Log "Failed to add license. Attempt $retryCount of $maxRetries. Waiting 15 seconds before retry..." -Level Warning
                            Start-Sleep -Seconds 15
                        }
                        else {
                            Write-Log "Failed to add license $skuPartNumber after $maxRetries attempts: $_" -Level Error
                            # Do not throw error, skip license assignment
                            # throw $_
                        }
                    }
                }
                
                # Verify license assignment
                $verifyLicense = Get-MgUserLicenseDetail -UserId $userId
                if ($verifyLicense.SkuId -contains $skuId) {
                    Write-Log "License verification successful for $skuPartNumber" -Level Success
                }
                else {
                    Write-Log "License verification failed for $skuPartNumber" -Level Error
                }
            }
            catch {
                Write-Log "Failed to process license $skuPartNumber`: $_" -Level Error
            }
        }

        # Add Azure RBAC roles
        Write-Log "`nApplying Azure RBAC roles..." -Level Info
        foreach ($role in $Attributes.AzureRoles) {
            try {
                Write-Log "Adding role: $($role.roleName) at scope: $($role.scope)" -Level Info
                az role assignment create --role $role.roleName --assignee $UPN --scope $role.scope
                Write-Log "Successfully added Azure role: $($role.roleName)" -Level Success
            }
            catch {
                Write-Log "Failed to add Azure role $($role.roleName)`: $_" -Level Error
            }
        }

        # Add Enterprise Application assignments
        Write-Log "`nApplying Enterprise Application assignments..." -Level Info
        foreach ($app in $Attributes.EnterpriseApps) {
            Write-Log "Processing application assignment: $($app.Application.DisplayName)" -Level Info
            
            try {
                if ([string]::IsNullOrEmpty($app.Assignment.AppRoleId) -or $app.Assignment.AppRoleId -eq "00000000-0000-0000-0000-000000000000") {
                    # For applications without specific role IDs, use a different approach
                    $params = @{
                        "principalId" = $userId
                        "resourceId" = $app.Assignment.ResourceId
                        "appRoleId" = "00000000-0000-0000-0000-000000000000"
                    }
                    
                    # Check if assignment already exists
                    $existingAssignment = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $app.Assignment.ResourceId | 
                        Where-Object { $_.PrincipalId -eq $userId }
                        
                    if (-not $existingAssignment) {
                        New-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $app.Assignment.ResourceId -BodyParameter $params -ErrorAction Stop
                        Write-Log "Successfully added application assignment: $($app.Application.DisplayName)" -Level Success
                    } else {
                        Write-Log "Assignment already exists for $($app.Application.DisplayName)" -Level Info
                    }
                } else {
                    # For applications with specific role IDs
                    $params = @{
                        "principalId" = $userId
                        "resourceId" = $app.Assignment.ResourceId
                        "appRoleId" = $app.Assignment.AppRoleId
                    }
                    
                    # Check if assignment already exists
                    $existingAssignment = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $app.Assignment.ResourceId | 
                        Where-Object { $_.PrincipalId -eq $userId -and $_.AppRoleId -eq $app.Assignment.AppRoleId }
                        
                    if (-not $existingAssignment) {
                        New-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $app.Assignment.ResourceId -BodyParameter $params -ErrorAction Stop
                        Write-Log "Successfully added application assignment: $($app.Application.DisplayName)" -Level Success
                    } else {
                        Write-Log "Assignment already exists for $($app.Application.DisplayName)" -Level Info
                    }
                }
            } catch {
                Write-Log "Failed to assign application $($app.Application.DisplayName). Error: $($_.Exception.Message)" -Level Warning
            }
        }

        # Final License Verification
        Write-Log "`nPerforming final license verification..." -Level Info
        
        $finalTargetLicenses = Get-MgUserLicenseDetail -UserId $UPN
        
        Write-Log "Source user ($($Attributes.SourceUPN)) licenses:" -Level Info
        foreach ($license in $SourceLicenses) {
            Write-Log "- $($license.SkuPartNumber) ($($license.SkuId))" -Level Info
        }
        
        Write-Log "Target user ($UPN) licenses:" -Level Info
        foreach ($license in $finalTargetLicenses) {
            Write-Log "- $($license.SkuPartNumber) ($($license.SkuId))" -Level Info
        }
        
        # Compare licenses
        $sourceLicenseIds = $SourceLicenses.SkuId
        $targetLicenseIds = $finalTargetLicenses.SkuId
        
        $missingLicenses = $sourceLicenseIds | Where-Object { $_ -notin $targetLicenseIds }
        
        if ($missingLicenses) {
            Write-Log "`nWarning: Some licenses were not migrated:" -Level Warning
            foreach ($licenseId in $missingLicenses) {
                $licenseName = ($SourceLicenses | Where-Object { $_.SkuId -eq $licenseId }).SkuPartNumber
                Write-Log "- $licenseName ($licenseId)" -Level Warning
            }
        }
        else {
            Write-Log "`nAll licenses were successfully migrated!" -Level Success
        }

        Write-Log "`nSuccessfully applied all attributes" -Level Success
    }
    catch {
        Write-Log "Error applying user attributes: $_" -Level Error
        throw $_
    }
}

function Start-UserMigration {
    param (
        [string]$OldUPN,
        [string]$NewUPN
    )
    
    Write-Log "Starting user migration from $OldUPN to $NewUPN" -Level Info
    
    # Get all source user information first
    Write-Log "Collecting attributes from $OldUPN..." -Level Info
    $sourceAttributes = Get-UserAttributes -UPN $OldUPN
    
    if (-not $sourceAttributes) {
        Write-Log "Failed to collect source user attributes. Migration cannot proceed." -Level Error
        return $false
    }
    
    # Get source user's licenses before deletion
    Write-Log "Getting source user's license information..." -Level Info
    $sourceLicenses = Get-UserLicensesWithRetry -UserPrincipalName $OldUPN
    Write-Log "Successfully retrieved source user's licenses" -Level Success
    
    # Now remove the old user
    Write-Log "Removing old user $OldUPN..." -Level Info
    Remove-OldUser -UPN $OldUPN -SourceLicenses $sourceLicenses
    
    Write-Log "Pausing for 15 seconds to allow licenses to be released..." -Level Info
    Start-Sleep -Seconds 15
    
    # Apply attributes to new user
    Write-Log "Applying attributes to $NewUPN..." -Level Info
    $success = Set-UserAttributes -UPN $NewUPN -Attributes $sourceAttributes -SourceLicenses $sourceLicenses
    
    if ($success) {
        Write-Log "User migration completed successfully!" -Level Success
        Write-Log "`n=== Migration Complete ===" -Level Success
        return $true
    }
    else {
        Write-Log "User migration completed with errors. Please check the logs." -Level Warning
        Write-Log "`n=== Migration Complete with Errors ===" -Level Warning
        return $false
    }
}

# Main script execution
try {
    Write-Log "=== Azure User Migration Script Started ===" -Level Info
    Write-Log "Source UPN: $OldUPN" -Level Info
    Write-Log "Target UPN: $NewUPN" -Level Info

    Start-UserMigration -OldUPN $OldUPN -NewUPN $NewUPN

    Write-Log "`n=== Migration Complete ===" -Level Success
}
catch {
    Write-Log "Migration failed: $_" -Level Error
    exit 1
}
