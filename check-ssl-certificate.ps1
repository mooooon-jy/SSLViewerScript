[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$HostName,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65535)]
    [int]$Port,

    [string]$ConnectHost,

    [int]$TimeoutMilliseconds = 10000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($null -eq ('TlsCertificateValidation' -as [type])) {
    Add-Type -TypeDefinition @'
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class TlsCertificateValidation
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

if ([string]::IsNullOrWhiteSpace($ConnectHost)) {
    $ConnectHost = $HostName
}

$tcp = $null
$ssl = $null
try {
    Write-Host "TCP 연결: $ConnectHost`:$Port"
    Write-Host "SNI 이름 : $HostName"

    $tcp = [System.Net.Sockets.TcpClient]::new()
    $connect = $tcp.BeginConnect($ConnectHost, $Port, $null, $null)
    if (-not $connect.AsyncWaitHandle.WaitOne($TimeoutMilliseconds)) {
        throw "TCP connection timeout."
    }
    $tcp.EndConnect($connect)

    $validationCallback = [TlsCertificateValidation]::CreateCallback()
    $ssl = [System.Net.Security.SslStream]::new(
        $tcp.GetStream(),
        $false,
        $validationCallback
    )
    $authenticate = $ssl.AuthenticateAsClientAsync($HostName)
    if (-not $authenticate.Wait($TimeoutMilliseconds)) {
        throw "TLS handshake timeout."
    }
    $authenticate.GetAwaiter().GetResult()

    if ($null -eq $ssl.RemoteCertificate) {
        throw "The server did not return a certificate."
    }

    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
    $daysRemaining = [math]::Floor(($certificate.NotAfter.ToUniversalTime() - [DateTime]::UtcNow).TotalDays)

    Write-Host ""
    Write-Host "Certificate check succeeded." -ForegroundColor Green
    Write-Host "Subject  : $($certificate.Subject)"
    Write-Host "Issuer   : $($certificate.Issuer)"
    Write-Host "Valid from: $($certificate.NotBefore.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC"
    Write-Host "Expires   : $($certificate.NotAfter.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC"
    Write-Host "Remaining : $daysRemaining days"
}
catch {
    $rootException = $_.Exception.GetBaseException()
    Write-Host ""
    Write-Host "Certificate check failed." -ForegroundColor Red
    Write-Host "Type      : $($rootException.GetType().FullName)" -ForegroundColor Yellow
    Write-Host "Message   : $($rootException.Message)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Check DNS/hosts, firewall, actual TLS port, SNI hostname, and proxy routing."
    exit 1
}
finally {
    if ($null -ne $ssl) { $ssl.Dispose() }
    if ($null -ne $tcp) { $tcp.Dispose() }
}
