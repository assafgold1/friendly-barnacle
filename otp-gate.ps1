<#
  OtpGate - keeps RDP closed to the internet and opens it, per IP and for a few minutes,
  to whoever sends a valid Google Authenticator (TOTP) code. Pure PowerShell, nothing third-party.

    .\otp-gate.ps1 -Install     create the secret, verify a code from the app, start the gate service
    .\otp-gate.ps1 -Lockdown    close RDP to everyone except IPs the gate opened
    .\otp-gate.ps1 -Status      show service state, open IPs and the recent log
    .\otp-gate.ps1 -Uninstall   remove everything and restore the original RDP firewall rules

  Optional with -Install:  -GatePort 47123  -AccessMinutes 10

  Used by the Proxmox installer (install.sh) through the QEMU guest agent:
    -Install -Unattended        no prompts; secret.txt is written beforehand by the installer
    -Verify -Code 123456        exit code 0 if the code matches the secret
    -Lockdown -Force            skip the "type YES" safety prompt
#>
[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Lockdown,
    [switch]$Status,
    [switch]$Uninstall,
    [switch]$Verify,
    [switch]$Run,
    [switch]$Unattended,
    [switch]$Force,
    [string]$Code,
    [int]$GatePort = 47123,
    [int]$AccessMinutes = 10
)
$ErrorActionPreference = 'Stop'

$ThisScript      = $PSCommandPath
$Root            = Join-Path $env:ProgramData 'OtpGate'
$SecretPath      = Join-Path $Root 'secret.txt'
$ConfigPath      = Join-Path $Root 'config.xml'
$LogPath         = Join-Path $Root 'gate.log'
$DisabledPath    = Join-Path $Root 'disabled-rules.txt'
$InstalledScript = Join-Path $Root 'otp-gate.ps1'
$TaskName        = 'OtpGate'
$RuleGroup       = 'OtpGate'
$Base32Alphabet  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

# Gate state (lives in the -Run process)
$script:LastUsedStep = 0
$script:Failures     = @{}   # ip -> failure timestamps
$script:AllFailures  = @()   # failure timestamps from every ip

# Brute-force limits: per IP, and across all IPs (a botnet spreads its guesses)
$MaxFailuresPerIp = 5
$MaxFailuresTotal = 20
$FailureWindowMin = 10

# ---------------------------------------------------------------- TOTP (RFC 6238)

function ConvertTo-Base32([byte[]]$Bytes) {
    $sb = New-Object System.Text.StringBuilder
    $bits = 0; $value = 0
    foreach ($b in $Bytes) {
        $value = ($value -shl 8) -bor $b
        $bits += 8
        while ($bits -ge 5) {
            $bits -= 5
            [void]$sb.Append($Base32Alphabet[($value -shr $bits) -band 31])
        }
        $value = $value -band ((1 -shl $bits) - 1)
    }
    if ($bits -gt 0) { [void]$sb.Append($Base32Alphabet[($value -shl (5 - $bits)) -band 31]) }
    $sb.ToString()
}

function ConvertFrom-Base32([string]$Text) {
    $bytes = New-Object System.Collections.Generic.List[byte]
    $bits = 0; $value = 0
    foreach ($c in ($Text -replace '[\s=]', '').ToUpper().ToCharArray()) {
        $i = $Base32Alphabet.IndexOf($c)
        if ($i -lt 0) { throw "Invalid character in secret: '$c'" }
        $value = ($value -shl 5) -bor $i
        $bits += 5
        if ($bits -ge 8) {
            $bits -= 8
            $bytes.Add([byte](($value -shr $bits) -band 0xFF))
            $value = $value -band ((1 -shl $bits) - 1)
        }
    }
    , $bytes.ToArray()
}

function Get-UnixTime { [long][Math]::Floor(([DateTime]::UtcNow.Ticks - 621355968000000000) / 10000000) }

function Get-TotpCode([byte[]]$Key, [long]$Step) {
    $msg = [BitConverter]::GetBytes($Step)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($msg) }
    $hmac = New-Object System.Security.Cryptography.HMACSHA1 (, $Key)
    $h = $hmac.ComputeHash($msg)
    $o = $h[$h.Length - 1] -band 0x0F
    $bin = (([int]$h[$o] -band 0x7F) -shl 24) -bor ([int]$h[$o + 1] -shl 16) -bor ([int]$h[$o + 2] -shl 8) -bor [int]$h[$o + 3]
    '{0:D6}' -f ($bin % 1000000)
}

# Returns the matching 30-second step (one step of clock drift allowed each way), or $null.
# Steps at or before the last accepted one are rejected, so a code can't be replayed.
function Find-TotpStep([byte[]]$Key, [string]$Code, [long]$UnixTime = (Get-UnixTime)) {
    if ($Code -notmatch '^\d{6}$') { return $null }
    $now = [long][Math]::Floor($UnixTime / 30)
    foreach ($step in ($now - 1), $now, ($now + 1)) {
        if ($step -le $script:LastUsedStep) { continue }
        if ((Get-TotpCode $Key $step) -eq $Code) { return $step }
    }
    $null
}

# ---------------------------------------------------------------- helpers

function Write-Log([string]$Message) {
    if ((Test-Path $LogPath) -and (Get-Item $LogPath).Length -gt 1MB) { Move-Item $LogPath "$LogPath.old" -Force }
    Add-Content -Path $LogPath -Value ('{0:yyyy-MM-dd HH:mm:ss}  {1}' -f (Get-Date), $Message)
}

function Assert-Admin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this from PowerShell opened with "Run as administrator".'
    }
}

function Get-RdpPort {
    [int](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').PortNumber
}

function Get-GateRules {
    @(Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'OtpGate-Allow-*' })
}

# Enabled inbound allow rules, other than ours, that let anyone reach the RDP port
function Get-OpenRdpRules([int]$RdpPort) {
    @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
        Where-Object { $_.Group -ne $RuleGroup } |
        Where-Object { @(($_ | Get-NetFirewallPortFilter).LocalPort) -contains [string]$RdpPort })
}

# ---------------------------------------------------------------- gate service

function Grant-Access([string]$Ip) {
    $name = 'OtpGate-Allow-' + ($Ip -replace '[^0-9A-Za-z]', '_')
    $expires = [string][DateTime]::UtcNow.AddMinutes($script:Config.AccessMinutes).Ticks
    if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) {
        Set-NetFirewallRule -Name $name -Description $expires
    } else {
        New-NetFirewallRule -Name $name -DisplayName "OtpGate allow $Ip" -Group $RuleGroup -Description $expires `
            -Direction Inbound -Protocol TCP -LocalPort $script:Config.RdpPort -RemoteAddress $Ip -Action Allow | Out-Null
    }
}

function Remove-ExpiredAccess {
    foreach ($rule in Get-GateRules) {
        $expires = $rule.Description -as [long]
        if ($expires -and $expires -gt [DateTime]::UtcNow.Ticks) { continue }
        $ip = @(($rule | Get-NetFirewallAddressFilter).RemoteAddress)[0]
        # Keep the door open while an RDP session from that IP is still connected
        if (Get-NetTCPConnection -LocalPort $script:Config.RdpPort -RemoteAddress $ip -State Established -ErrorAction SilentlyContinue) {
            Set-NetFirewallRule -Name $rule.Name -Description ([string][DateTime]::UtcNow.AddMinutes(5).Ticks)
            continue
        }
        Remove-NetFirewallRule -Name $rule.Name
        Write-Log "closed RDP for $ip"
    }
}

function Test-Blocked([string]$Ip) {
    $cutoff = [DateTime]::UtcNow.AddMinutes(-$FailureWindowMin)
    foreach ($k in @($script:Failures.Keys)) {
        $recent = @($script:Failures[$k] | Where-Object { $_ -gt $cutoff })
        if ($recent.Count) { $script:Failures[$k] = $recent } else { $script:Failures.Remove($k) }
    }
    $script:AllFailures = @($script:AllFailures | Where-Object { $_ -gt $cutoff })
    ($script:Failures.ContainsKey($Ip) -and $script:Failures[$Ip].Count -ge $MaxFailuresPerIp) -or
        ($script:AllFailures.Count -ge $MaxFailuresTotal)
}

function Add-Failure([string]$Ip) {
    $now = [DateTime]::UtcNow
    if ($script:Failures.ContainsKey($Ip)) { $script:Failures[$Ip] += $now } else { $script:Failures[$Ip] = @($now) }
    $script:AllFailures += $now
}

# Protocol: client sends "123456\n", gate answers "OK <minutes>", "DENIED" or "BLOCKED"
function Invoke-GateRequest([System.Net.Sockets.TcpClient]$Client) {
    $ip = $Client.Client.RemoteEndPoint.Address.ToString()
    $Client.ReceiveTimeout = 5000
    $Client.SendTimeout = 5000
    $stream = $Client.GetStream()
    $writer = New-Object System.IO.StreamWriter($stream)
    $writer.NewLine = "`n"
    $writer.AutoFlush = $true

    if (Test-Blocked $ip) {
        $writer.WriteLine('BLOCKED')
        Write-Log "refused $ip (too many wrong codes)"
        return
    }

    $buffer = New-Object byte[] 32
    $count = 0
    while ($count -lt $buffer.Length) {
        $read = $stream.Read($buffer, $count, $buffer.Length - $count)
        if ($read -le 0) { break }
        $count += $read
        if ([Array]::IndexOf($buffer, [byte]10, 0, $count) -ge 0) { break }
    }
    $code = [Text.Encoding]::ASCII.GetString($buffer, 0, $count).Trim()

    $step = Find-TotpStep $script:Key $code
    if ($null -ne $step) {
        $script:LastUsedStep = $step
        Grant-Access $ip
        $writer.WriteLine("OK $($script:Config.AccessMinutes)")
        Write-Log "opened RDP for $ip"
    } else {
        Add-Failure $ip
        $writer.WriteLine('DENIED')
        Write-Log "wrong code from $ip"
    }
}

function Start-Gate {
    $script:Config = Import-Clixml $ConfigPath
    $script:Key = ConvertFrom-Base32 (Get-Content $SecretPath -Raw).Trim()
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $script:Config.GatePort)
    $listener.Start()
    Write-Log "gate listening on port $($script:Config.GatePort) (RDP port $($script:Config.RdpPort))"
    try {
        $nextCleanup = [DateTime]::MinValue
        while ($true) {
            if ([DateTime]::UtcNow -ge $nextCleanup) {
                try { Remove-ExpiredAccess } catch { Write-Log "cleanup error: $_" }
                $nextCleanup = [DateTime]::UtcNow.AddSeconds(30)
            }
            if (-not $listener.Pending()) { Start-Sleep -Milliseconds 200; continue }
            $client = $listener.AcceptTcpClient()
            try { Invoke-GateRequest $client } catch { Write-Log "request error: $_" } finally { $client.Close() }
        }
    } finally {
        $listener.Stop()
    }
}

# ---------------------------------------------------------------- install / manage

function Install-Gate {
    Assert-Admin
    New-Item -ItemType Directory -Force -Path $Root | Out-Null
    # Only SYSTEM and Administrators may read this folder - it holds the secret
    icacls $Root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null

    if (Test-Path $SecretPath) {
        $secret = (Get-Content $SecretPath -Raw).Trim()
        Write-Host 'Keeping the existing secret (delete secret.txt and reinstall to create a new one).'
    } else {
        $bytes = New-Object byte[] 20
        (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($bytes)
        $secret = ConvertTo-Base32 $bytes
        [IO.File]::WriteAllText($SecretPath, $secret)
    }
    $key = ConvertFrom-Base32 $secret

    if (-not $Unattended) {
        Write-Host ''
        Write-Host 'In Google Authenticator tap  +  >  Enter a setup key' -ForegroundColor Cyan
        Write-Host "  Account : $env:COMPUTERNAME RDP"
        Write-Host "  Key     : $((($secret -split '(.{4})') | Where-Object { $_ }) -join ' ')"
        Write-Host '  Type    : Time based'
        Write-Host ''
        do {
            $answer = Read-Host 'Enter the 6-digit code the app shows now (q to abort)'
            if ($answer -eq 'q') { Write-Host 'Aborted - nothing was enabled.'; return }
            $ok = $null -ne (Find-TotpStep $key $answer.Trim())
            if (-not $ok) { Write-Host 'Wrong code, try again.' -ForegroundColor Yellow }
        } until ($ok)
    }

    $rdpPort = Get-RdpPort
    Export-Clixml -Path $ConfigPath -InputObject @{ GatePort = $GatePort; AccessMinutes = $AccessMinutes; RdpPort = $rdpPort }
    if ($ThisScript -ne $InstalledScript) { Copy-Item -Path $ThisScript -Destination $InstalledScript -Force }

    Get-NetFirewallRule -Name 'OtpGate-Listener' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -Name 'OtpGate-Listener' -DisplayName "OtpGate listener (TCP $GatePort)" -Group $RuleGroup `
        -Direction Inbound -Protocol TCP -LocalPort $GatePort -Action Allow | Out-Null

    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' `
                     -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstalledScript`" -Run"
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 `
                     -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
    Start-ScheduledTask -TaskName $TaskName

    Start-Sleep -Seconds 3
    if (Get-NetTCPConnection -LocalPort $GatePort -State Listen -ErrorAction SilentlyContinue) {
        Write-Host "Gate is running on TCP $GatePort." -ForegroundColor Green
    } else {
        Write-Warning "Gate is not listening yet - check $LogPath"
    }
    if ($Unattended) { return }
    Write-Host ''
    Write-Host 'Next:'
    Write-Host "  1. From your Mac run vps-connect and make sure you get OK. RDP is still open to everyone for now."
    Write-Host "  2. Reconnect RDP right after a successful vps-connect, then run:  & '$InstalledScript' -Lockdown"
    Write-Host "  If the VM sits behind NAT on the Proxmox host, forward TCP $GatePort to it like 3389."
}

function Enable-Lockdown {
    Assert-Admin
    if (-not (Test-Path $ConfigPath)) { throw 'Run -Install first.' }
    $config = Import-Clixml $ConfigPath

    $off = @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled -or $_.DefaultInboundAction -eq 'Allow' })
    if ($off) { throw "Windows Firewall is off or allows all inbound on: $($off.Name -join ', '). Fix that first or RDP stays open." }
    if (-not (Get-NetTCPConnection -LocalPort $config.GatePort -State Listen -ErrorAction SilentlyContinue)) {
        throw 'The gate service is not listening - locking down now would shut you out. Check -Status.'
    }

    # Make sure the session we're in came through the gate, so it survives the lockdown
    $gateIps = @(Get-GateRules | Get-NetFirewallAddressFilter | ForEach-Object { $_.RemoteAddress })
    $sessionIps = @(Get-NetTCPConnection -LocalPort $config.RdpPort -State Established -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty RemoteAddress -Unique)
    $outside = @($sessionIps | Where-Object { $gateIps -notcontains $_ })
    if ($outside) {
        Write-Warning "RDP connection from $($outside -join ', ') was not opened by the gate and may be cut off."
        Write-Warning 'Run vps-connect from your Mac first, reconnect, then lock down. (Proxmox console still works if anything goes wrong.)'
        if (-not $Force -and (Read-Host 'Type YES to lock down anyway') -ne 'YES') { return }
    }

    $rules = Get-OpenRdpRules $config.RdpPort
    foreach ($rule in $rules) {
        Disable-NetFirewallRule -Name $rule.Name
        Add-Content -Path $DisabledPath -Value $rule.Name
        Write-Host "Disabled: $($rule.DisplayName)"
    }
    if (-not $rules) { Write-Host 'No open RDP rules found - already locked down.' }
    Write-Log 'lockdown enabled'
    Write-Host 'RDP is now reachable only through the gate.' -ForegroundColor Green
}

function Show-Status {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Write-Host ("Service  : " + $(if ($task) { $task.State } else { 'not installed' }))
    if (-not (Test-Path $ConfigPath)) { return }
    $config = Import-Clixml $ConfigPath

    $listening = Get-NetTCPConnection -LocalPort $config.GatePort -State Listen -ErrorAction SilentlyContinue
    Write-Host ("Gate     : TCP $($config.GatePort) " + $(if ($listening) { 'listening' } else { 'NOT listening' }))

    $open = Get-OpenRdpRules $config.RdpPort
    if ($open) { Write-Host "RDP      : OPEN TO EVERYONE via: $(($open | ForEach-Object DisplayName) -join ', ')" -ForegroundColor Yellow }
    else       { Write-Host "RDP      : closed except for gate-opened IPs" -ForegroundColor Green }

    foreach ($rule in Get-GateRules) {
        $ip = @(($rule | Get-NetFirewallAddressFilter).RemoteAddress)[0]
        $until = (New-Object DateTime -ArgumentList ([long]$rule.Description), ([DateTimeKind]::Utc)).ToLocalTime()
        Write-Host ("Open for : {0} until {1:HH:mm}" -f $ip, $until)
    }
    if (Test-Path $LogPath) { Write-Host ''; Get-Content $LogPath -Tail 10 }
}

function Test-Code {
    $key = ConvertFrom-Base32 (Get-Content $SecretPath -Raw).Trim()
    if ($null -ne (Find-TotpStep $key "$Code".Trim())) { Write-Host 'OK'; exit 0 }
    Write-Host 'WRONG'
    exit 1
}

function Uninstall-Gate {
    Assert-Admin
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    # Reopen the original RDP rules before removing ours, so there's no moment without access
    if (Test-Path $DisabledPath) {
        foreach ($name in Get-Content $DisabledPath) {
            Enable-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
            Write-Host "Re-enabled: $name"
        }
    }
    Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Remove-Item $Root -Recurse -Force
    Write-Host 'OtpGate removed.' -ForegroundColor Green
}

# ---------------------------------------------------------------- entry point

if ($Run) {
    # Never exit: on any crash, log it and start listening again
    while ($true) {
        try { Start-Gate } catch { Write-Log "gate crashed: $_"; Start-Sleep -Seconds 10 }
    }
}
elseif ($Install)   { Install-Gate }
elseif ($Lockdown)  { Enable-Lockdown }
elseif ($Status)    { Show-Status }
elseif ($Verify)    { Test-Code }
elseif ($Uninstall) { Uninstall-Gate }
else {
    Write-Host 'Usage: .\otp-gate.ps1 -Install | -Lockdown | -Status | -Uninstall'
}
