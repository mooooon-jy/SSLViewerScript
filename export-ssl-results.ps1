[CmdletBinding()]
param(
    [string]$InputFile = '.\업무망_내부.md',
    [string]$OutputFile = '.\ssl-results.json',
    [int]$TimeoutMilliseconds = 10000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($null -eq ('TlsCertificateValidationExport' -as [type])) {
    Add-Type -TypeDefinition @'
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class TlsCertificateValidationExport
{
    public static RemoteCertificateValidationCallback CreateCallback()
    {
        return delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
        {
            return true;
        };
    }
}
'@
}

function Get-ColumnValues {
    param($Row)
    return @($Row.PSObject.Properties | ForEach-Object { [string]$_.Value })
}

function Get-CertificateResult {
    param(
        [string]$Id,
        [string]$HostName,
        [int]$Port,
        [string]$ConnectHost,
        [string]$Name,
        [string]$Environment
    )

    $tcp = $null
    $ssl = $null
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $connect = $tcp.BeginConnect($ConnectHost, $Port, $null, $null)
        if (-not $connect.AsyncWaitHandle.WaitOne($TimeoutMilliseconds)) {
            throw 'TCP connection timeout.'
        }
        $tcp.EndConnect($connect)

        $ssl = [System.Net.Security.SslStream]::new(
            $tcp.GetStream(),
            $false,
            [TlsCertificateValidationExport]::CreateCallback()
        )
        $authenticate = $ssl.AuthenticateAsClientAsync($HostName)
        if (-not $authenticate.Wait($TimeoutMilliseconds)) {
            throw 'TLS handshake timeout.'
        }
        $authenticate.GetAwaiter().GetResult()

        if ($null -eq $ssl.RemoteCertificate) {
            throw 'The server did not return a certificate.'
        }

        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
        $notBefore = $certificate.NotBefore.ToUniversalTime()
        $notAfter = $certificate.NotAfter.ToUniversalTime()
        $daysRemaining = [math]::Floor(($notAfter - [DateTime]::UtcNow).TotalDays)
        return [ordered]@{
            id = $Id
            name = $Name
            environment = $Environment
            hostname = $HostName
            port = $Port
            connectHost = $ConnectHost
            source = 'windows-powershell'
            ok = $true
            notBefore = $notBefore.ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
            notAfter = $notAfter.ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
            daysRemaining = $daysRemaining
            subject = $certificate.Subject
            issuer = $certificate.Issuer
        }
    }
    catch {
        $rootException = $_.Exception.GetBaseException()
        return [ordered]@{
            id = $Id
            name = $Name
            environment = $Environment
            hostname = $HostName
            port = $Port
            connectHost = $ConnectHost
            source = 'windows-powershell'
            ok = $false
            error = $rootException.Message
        }
    }
    finally {
        if ($null -ne $ssl) { $ssl.Dispose() }
        if ($null -ne $tcp) { $tcp.Dispose() }
    }
}

$resolvedInput = [System.IO.Path]::GetFullPath($InputFile)
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputFile)
$productionEnvironment = [string][char]0xC6B4 + [string][char]0xC601
$text = [System.IO.File]::ReadAllText($resolvedInput, [System.Text.Encoding]::UTF8)
$rows = @(ConvertFrom-Csv -InputObject $text -Delimiter "`t")
$results = [System.Collections.Generic.List[object]]::new()

foreach ($row in $rows) {
    $values = Get-ColumnValues $row
    if ($values.Count -lt 13 -or $values[4] -ne $productionEnvironment) {
        continue
    }

    $name = $values[2].Trim()
    $domain = $values[3].Trim().ToLowerInvariant()
    $ipAddress = $values[6].Trim()
    $hostname = "$name.$domain"
    $connectHost = if ($ipAddress -match '^[0-9a-fA-F:.]+$') { $ipAddress } else { $hostname }
    $ports = [regex]::Matches($values[12], '\d+') | ForEach-Object { [int]$_.Value } | Select-Object -Unique

    foreach ($port in $ports) {
        $rowNumber = [array]::IndexOf($rows, $row) + 2
        $id = "$rowNumber-$port"
        Write-Host "Checking $hostname`:$port via $connectHost"
        $results.Add((Get-CertificateResult -Id $id -HostName $hostname -Port $port -ConnectHost $connectHost -Name $name -Environment $values[4]))
    }
}

$document = [ordered]@{
    generatedAt = [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
    source = [System.IO.Path]::GetFileName($resolvedInput)
    environment = $productionEnvironment
    results = @($results)
}
$json = $document | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText($resolvedOutput, $json, [System.Text.UTF8Encoding]::new($false))
Write-Host ""
Write-Host "Saved $($results.Count) results to $resolvedOutput"
