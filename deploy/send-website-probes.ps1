param(
    [Parameter(Mandatory)][string]$Runtime,
    [Parameter(Mandatory)][string]$Receiver,
    [Parameter(Mandatory)][string]$SourceAddress
)

$ErrorActionPreference = 'Stop'
$urls = @(
    'https://pgs.gosuslugi.ru/',
    'https://nspd.gov.ru/map?thematic=PKK&coordinate_x=7804891.637510094&coordinate_y=8181287.398947453&zoom=5&baseLayerId=235'
)
$checkedAt = [DateTimeOffset]::UtcNow.ToString('o')
$sites = foreach ($url in $urls) {
    $body = [IO.Path]::GetTempFileName()
    try {
        $curlArgs = @('--disable', '--globoff', '--noproxy', '*', '--proto', '=https',
            '--interface', $SourceAddress, '--location', '--proto-redir', '=https', '--max-redirs', '3',
            '--max-time', '12', '--max-filesize', '2097152', '--silent',
            '--output', $body, '--write-out', '%{json}', '--url', $url)
        $raw = & "$env:SystemRoot/System32/curl.exe" @curlArgs
        $code = $LASTEXITCODE
        $info = if ($raw) { $raw | ConvertFrom-Json } else { @{} }
        $http = if ($info.http_code) { [int]$info.http_code } else { $null }
        $type = ([string]$info.content_type -split ';')[0].Trim().ToLowerInvariant()
        $htmlType = $type -in @('text/html', 'application/xhtml+xml')
        $bytes = (Get-Item -LiteralPath $body).Length
        $tls = if ($code -in @(35, 51, 60, 77, 83, 90, 91)) { 'failed' } elseif ($http) { 'verified' } else { 'unconfirmed' }
        $status = if ($tls -eq 'failed') { 'tls_error' }
            elseif ($code -eq 28) { 'timeout' }
            elseif ($code) { 'connection_error' }
            elseif ($http -in @(401, 403, 429)) { 'blocked' }
            elseif ($http -ne 200) { 'http_error' }
            elseif (!$htmlType -or !(Select-String -LiteralPath $body -Pattern '<(?:!doctype\s+html\b|html\b)' -Quiet)) { 'not_html' }
            elseif (Select-String -LiteralPath $body -Pattern 'checking your browser|cf-chl-|/cdn-cgi/challenge-platform|just a moment' -Quiet) { 'challenge' }
            else { 'ok' }
        @{
            url = $url
            status = $status
            http_status = $http
            body_bytes = [Math]::Min($bytes, 2097152)
            content_type = if ($htmlType) { $type } else { '' }
            tls = $tls
            total_ms = [int]([double]$info.time_total * 1000)
        }
    } finally {
        Remove-Item -LiteralPath $body
    }
}
$ssh = Join-Path $env:SystemRoot 'System32/OpenSSH/ssh.exe'
$receipt = @{checked_at = $checkedAt; sites = @($sites)} | ConvertTo-Json -Compress -Depth 4
$options = @('-T', '-F', 'NUL', '-b', $SourceAddress, '-i', (Join-Path $Runtime 'website-receiver.key'),
    '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
    '-o', "UserKnownHostsFile=$(Join-Path $Runtime 'known_hosts')", '-o', 'ConnectTimeout=5')
$receipt | & $ssh @options $Receiver
exit $LASTEXITCODE
