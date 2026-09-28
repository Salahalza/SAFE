$ErrorActionPreference = 'SilentlyContinue'
Write-Host "Installing OpenSSH Server..."
$capability = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
if ($capability -and $capability.State -ne 'Installed') {
    Add-WindowsCapability -Online -Name $capability.Name
}
Set-Service -Name sshd -StartupType 'Automatic'
Start-Service sshd
New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -DisplayName "OpenSSH Server (sshd)" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
Write-Host "SSH Configuration Complete!"
