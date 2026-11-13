param(
    [Parameter(Mandatory)][string]$Runtime,
    [Parameter(Mandatory)][string]$Origin,
    [Parameter(Mandatory)][string]$Profile,
    [Parameter(Mandatory)][string]$Receiver,
    [Parameter(Mandatory)][string]$SourceAddress
)

$ErrorActionPreference = 'Stop'
$python = Join-Path $Runtime 'Scripts\python.exe'
$ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
$key = Join-Path $Runtime 'receiver.key'
$knownHosts = Join-Path $Runtime 'known_hosts'
$config = Join-Path $Runtime 'profile.json'
Push-Location $Runtime
try {
    $receipt = & $python -s -B -m app.network_route_spool measure $Origin $Profile --config $config
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $options = @(
        '-T', '-F', 'NUL', '-b', $SourceAddress, '-i', $key,
        '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
        '-o', "UserKnownHostsFile=$knownHosts", '-o', 'ConnectTimeout=5'
    )
    $receipt | & $ssh @options $Receiver
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
