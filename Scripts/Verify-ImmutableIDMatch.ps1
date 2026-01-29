# Verify-ImmutableIDMatch.ps1 (Sanitized)
# Quick check to verify if a user's ImmutableID in Entra matches their AD ObjectGUID/ConsistencyGuid.

[CmdletBinding(DefaultParameterSetName = 'Single')]
param(
    [Parameter(Mandatory=$true, ParameterSetName='Single')]
    [string]$OnPremiseUPN,

    [Parameter(Mandatory=$true, ParameterSetName='Single')]
    [string]$EntraUPN,

    [Parameter(Mandatory=$true, ParameterSetName='Csv')]
    [string]$CsvPath,

    [Parameter(Mandatory=$false)]
    [string]$DomainControllerIP = "__DOMAIN_CONTROLLER__",

    [Parameter(Mandatory=$false, ParameterSetName='Csv')]
    [string]$OutCsvPath
)

$ErrorActionPreference = 'Stop'

function Invoke-VerifyImmutableIdMatch {
    param(
        [Parameter(Mandatory=$true)]
        [string]$OnPremiseUPN,

        [Parameter(Mandatory=$true)]
        [string]$EntraUPN,

        [Parameter(Mandatory=$true)]
        [pscredential]$DomainCredential,

        [Parameter(Mandatory=$true)]
        [string]$DomainControllerIP
    )

    $result = [pscustomobject]@{
        OnPremiseUPN = $OnPremiseUPN
        EntraUPN = $EntraUPN
        AD_ObjectGuid = $null
        AD_AnchorSource = $null
        AD_CalculatedImmutableId = $null
        Entra_OnPremisesImmutableId = $null
        Match = $false
        Status = 'Unknown'
        Message = $null
    }

    try {
        $adUser = Get-ADUser -Filter "UserPrincipalName -eq '$OnPremiseUPN'" -Server $DomainControllerIP -Credential $DomainCredential -Properties ObjectGUID,'mS-DS-ConsistencyGuid' -ErrorAction Stop
        if (-not $adUser) {
            $result.Status = 'Error'
            $result.Message = "User not found in AD with UPN: $OnPremiseUPN"
            return $result
        }

        $guid = $adUser.ObjectGUID
        $result.AD_ObjectGuid = $guid

        $consistencyBytes = $adUser.'mS-DS-ConsistencyGuid'
        $anchorFromConsistency = $null
        $anchorFromGuid = $null

        if ($consistencyBytes) {
            $result.AD_AnchorSource = 'mS-DS-ConsistencyGuid'
            $anchorFromConsistency = [System.Convert]::ToBase64String($consistencyBytes)
        }

        if ($guid) {
            $guidBytes = $guid.ToByteArray()
            $anchorFromGuid = [System.Convert]::ToBase64String($guidBytes)
        }

        $calculatedImmutableId = if ($anchorFromConsistency) { $anchorFromConsistency } else { $anchorFromGuid }
        $result.AD_CalculatedImmutableId = $calculatedImmutableId
        if (-not $result.AD_AnchorSource) { $result.AD_AnchorSource = 'ObjectGUID' }

        $entraUser = Get-MgUser -UserId $EntraUPN -Property "Id,UserPrincipalName,OnPremisesImmutableId" -ErrorAction Stop
        $result.Entra_OnPremisesImmutableId = $entraUser.OnPremisesImmutableId

        if ($entraUser.OnPremisesImmutableId -eq $calculatedImmutableId) {
            $result.Match = $true
            $result.Status = 'Match'
            $result.Message = 'ImmutableIDs are identical'
        } else {
            $result.Match = $false
            $result.Status = 'Mismatch'
            $result.Message = 'ImmutableIDs do not match'
        }
    } catch {
        $result.Status = 'Error'
        $result.Message = $_.Exception.Message
    }

    return $result
}

Import-Module Microsoft.Graph.Users -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

$domainCred = Get-Credential -Message "Enter credentials for on-premise AD"
Connect-MgGraph -Scopes @('User.Read.All') -NoWelcome -ErrorAction Stop

if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $rows = Import-Csv -Path $CsvPath
    $results = foreach ($row in $rows) {
        Invoke-VerifyImmutableIdMatch -OnPremiseUPN $row.OnPremiseUPN -EntraUPN $row.EntraUPN -DomainCredential $domainCred -DomainControllerIP $DomainControllerIP
    }

    $outPath = $OutCsvPath
    if ([string]::IsNullOrWhiteSpace($outPath)) {
        $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
        $outPath = Join-Path -Path $PSScriptRoot -ChildPath "ImmutableID_Verify_$ts.csv"
    }

    $results | Export-Csv -Path $outPath -NoTypeInformation
    Write-Host "Results exported to: $outPath"

} else {
    $result = Invoke-VerifyImmutableIdMatch -OnPremiseUPN $OnPremiseUPN -EntraUPN $EntraUPN -DomainCredential $domainCred -DomainControllerIP $DomainControllerIP
    $result
}
