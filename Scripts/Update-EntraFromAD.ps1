# Update-EntraFromAD.ps1 (Sanitized)
#
# PURPOSE:
#   Aligns the source anchor between on-prem AD and Entra ID users to avoid mail proxy duplicate errors.
#
# NOTE: This is a sanitized portfolio version.
#   Replace placeholders and validate in a non-production tenant before use.

param(
    [Parameter(Mandatory=$true)]
    [string]$OnPremiseUPN,

    [Parameter(Mandatory=$true)]
    [string]$EntraUPN,

    [Parameter(Mandatory=$false)]
    [string]$DomainControllerIP = "__DOMAIN_CONTROLLER__",

    [Parameter(Mandatory=$false)]
    [string]$AADConnectServer,

    [Parameter(Mandatory=$false)]
    [switch]$WhatIf,

    [Parameter(Mandatory=$false)]
    [switch]$SkipSync,

    [Parameter(Mandatory=$false)]
    [int]$WaitSecondsBetweenSyncs = 30,

    [Parameter(Mandatory=$false)]
    [int]$MaxWaitSecondsForSyncCompletion = 900,

    [Parameter(Mandatory=$false)]
    [int]$SyncStatusPollSeconds = 15,

    [Parameter(Mandatory=$false)]
    [switch]$FullSync,

    [Parameter(Mandatory=$false)]
    [switch]$PreserveDoNotSync,

    [Parameter(Mandatory=$false)]
    [ValidateSet('EntraToAd','AdToEntra')]
    [string]$SyncDirection = 'EntraToAd'
)

$ErrorActionPreference = 'Stop'

function Wait-ForADSyncIdle {
    param(
        [Parameter(Mandatory=$true)]
        [bool]$IsLocal,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        [Parameter(Mandatory=$true)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory=$true)]
        [int]$PollSeconds
    )

    if ($TimeoutSeconds -le 0) { return }

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $inProgress = $false
        try {
            if ($IsLocal) {
                Import-Module ADSync -ErrorAction Stop
                $scheduler = Get-ADSyncScheduler -ErrorAction Stop
                $inProgress = [bool]$scheduler.SyncCycleInProgress
            } else {
                $scheduler = Invoke-Command -Session $Session -ScriptBlock {
                    Import-Module ADSync -ErrorAction Stop
                    Get-ADSyncScheduler
                } -ErrorAction Stop
                $inProgress = [bool]$scheduler.SyncCycleInProgress
            }
        } catch {
            Start-Sleep -Seconds ([Math]::Max(5, $PollSeconds))
            continue
        }

        if (-not $inProgress) { return }
        Start-Sleep -Seconds ([Math]::Max(5, $PollSeconds))
    }
}

Import-Module Microsoft.Graph.Users -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

$domainCred = Get-Credential

$requiredScopes = @("User.ReadWrite.All", "Directory.ReadWrite.All")
Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop

$adUser = Get-ADUser -Filter "UserPrincipalName -eq '$OnPremiseUPN'" -Server $DomainControllerIP -Credential $domainCred -Properties ObjectGUID,'mS-DS-ConsistencyGuid',comment -ErrorAction Stop

$guid = $adUser.ObjectGUID
$guidBytes = $guid.ToByteArray()

$consistencyBytes = $adUser.'mS-DS-ConsistencyGuid'
$anchorFromConsistency = $null
if ($consistencyBytes) { $anchorFromConsistency = [System.Convert]::ToBase64String($consistencyBytes) }

$anchorFromGuid = [System.Convert]::ToBase64String($guidBytes)

$entraUser = Get-MgUser -UserId $EntraUPN -Property "Id,UserPrincipalName,OnPremisesImmutableId" -ErrorAction Stop
$entraImmutable = $entraUser.OnPremisesImmutableId

if ($SyncDirection -eq 'AdToEntra') {
    $anchorToPush = if ($anchorFromConsistency) { $anchorFromConsistency } else { $anchorFromGuid }
    if ($entraImmutable -ne $anchorToPush) {
        if (-not $WhatIf) {
            Update-MgUser -UserId $entraUser.Id -AdditionalProperties @{ onPremisesImmutableId = $anchorToPush } -ErrorAction Stop
        }
    }
} else {
    if ([string]::IsNullOrWhiteSpace($entraImmutable)) {
        throw "Entra onPremisesImmutableId is empty - cannot push anchor to AD"
    }

    if ($anchorFromConsistency -ne $entraImmutable) {
        if (-not $WhatIf) {
            $entraBytes = [System.Convert]::FromBase64String($entraImmutable)
            Set-ADUser -Identity $adUser.SamAccountName -Server $DomainControllerIP -Credential $domainCred -Replace @{ 'mS-DS-ConsistencyGuid' = $entraBytes } -ErrorAction Stop
        }
    }
}

# Optional: trigger AAD Connect sync cycles (placeholder)
# NOTE: Requires ADSync module on the target server.
$syncServer = if ($AADConnectServer) { $AADConnectServer } else { $DomainControllerIP }
$syncType = if ($FullSync) { "Initial" } else { "Delta" }

if (-not $SkipSync -and -not $WhatIf) {
    $syncSession = $null
    try {
        $syncSession = New-PSSession -ComputerName $syncServer -Credential $domainCred -ErrorAction Stop
        Invoke-Command -Session $syncSession -ScriptBlock {
            param($PolicyType)
            Import-Module ADSync -ErrorAction Stop
            Start-ADSyncSyncCycle -PolicyType $PolicyType
        } -ArgumentList $syncType -ErrorAction Stop

        Wait-ForADSyncIdle -IsLocal $false -Session $syncSession -TimeoutSeconds $MaxWaitSecondsForSyncCompletion -PollSeconds $SyncStatusPollSeconds
    } finally {
        if ($syncSession) { Remove-PSSession -Session $syncSession -ErrorAction SilentlyContinue }
    }
}
