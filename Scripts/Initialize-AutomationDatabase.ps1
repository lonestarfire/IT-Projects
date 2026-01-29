<#
.SYNOPSIS
    Initializes a SQL Database for automation logging and verifies connectivity.
.DESCRIPTION
    Sanitized portfolio version.

    NOTE: Replace placeholders and run against a non-production database first.
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$ServerName = "__SQL_SERVER_FQDN__",

    [Parameter(Mandatory=$true)]
    [string]$DatabaseName,

    [Parameter(Mandatory=$true)]
    [pscredential]$Credential
)

$connString = "Server=tcp:$ServerName,1433;Initial Catalog=$DatabaseName;Persist Security Info=False;User ID=$($Credential.UserName);Password=$($Credential.GetNetworkCredential().Password);MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"

$tableSchema = @"
IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[AutomationJobLog]') AND type in (N'U'))
BEGIN
    CREATE TABLE [dbo].[AutomationJobLog](
        [LogID] [int] IDENTITY(1,1) NOT NULL,
        [Timestamp] [datetime] DEFAULT GETDATE(),
        [Operation] [nvarchar](50) NOT NULL,
        [EmployeeId] [nvarchar](50) NOT NULL,
        [SamAccountName] [nvarchar](100) NULL,
        [UserPrincipalName] [nvarchar](100) NULL,
        [Status] [nvarchar](20) NOT NULL,
        [FinalOutput] [nvarchar](MAX) NULL,
        [AdditionalDetails] [nvarchar](MAX) NULL,
        [JobId] [nvarchar](100) NULL,
        PRIMARY KEY CLUSTERED ([LogID] ASC)
    )
END
"@

Write-Host "Connecting to $ServerName\\$DatabaseName..." -ForegroundColor Cyan

try {
    $conn = New-Object System.Data.SqlClient.SqlConnection($connString)
    $conn.Open()
    Write-Host "Connection Successful" -ForegroundColor Green

    Write-Host "Checking/Creating table 'AutomationJobLog'..."
    $cmd = $conn.CreateCommand()
    $cmd.CommandText = $tableSchema
    $null = $cmd.ExecuteNonQuery()
    Write-Host "Table schema verified." -ForegroundColor Green

    Write-Host "Inserting test record..."
    $testQuery = @"
INSERT INTO [dbo].[AutomationJobLog]
(Operation, EmployeeId, SamAccountName, UserPrincipalName, Status, FinalOutput, AdditionalDetails, JobId)
VALUES
('TEST-Connectivity', '0000', 'test.user', 'test.user@__DOMAIN_PRIMARY__', 'Success', 'Connectivity verified via PowerShell', 'Script execution', 'LOCAL-TEST')
"@

    $cmd.CommandText = $testQuery
    $rows = $cmd.ExecuteNonQuery()
    if ($rows -gt 0) { Write-Host "Test record inserted successfully" -ForegroundColor Green }

    $conn.Close()

} catch {
    Write-Error "Database Error: $($_.Exception.Message)"
    if ($_.Exception.InnerException) {
        Write-Error "Inner Exception: $($_.Exception.InnerException.Message)"
    }
}
