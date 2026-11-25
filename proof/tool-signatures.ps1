param([Parameter(Mandatory=$true)][string]$PathsJson,
      [Parameter(Mandatory=$true)][string]$OutputFile)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') { throw 'Disposable GitHub Windows runner required' }
$paths = Get-Content -LiteralPath $PathsJson -Raw | ConvertFrom-Json
$result = @{}
foreach ($item in $paths.PSObject.Properties) {
    $file = Get-Item -LiteralPath $item.Value
    $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
    $result[$item.Name] = @{
        path = $file.FullName
        bytes = $file.Length
        sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        file_version = $file.VersionInfo.FileVersion
        status = $signature.Status.ToString()
        signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { '' }
        certificate_thumbprint = if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { '' }
    }
}
$result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $OutputFile -Encoding utf8
