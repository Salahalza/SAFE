# configure_vm_ssh.ps1
# Run this script on the Host machine to fix or enable SSH inside the Test VM using PowerShell Direct.
# Requires Run As Administrator

param(
    [string]$VmName = "SAFE-TestVM",
    [string]$VmUser = "analyst"
)

# Check for Administrator privileges
$isAdmin = [bool](([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator on the Host."
    Exit 1
}

Write-Host "========================================="
Write-Host "   SAFE VM SSH Configuration Tool        "
Write-Host "========================================="
Write-Host ""
Write-Host "Configuring SSH inside VM: $VmName" -ForegroundColor Cyan
Write-Host "Please enter the credentials for the VM user '$VmUser' when prompted."

$cred = Get-Credential -UserName $VmUser -Message "Enter the VM credentials for $VmName"

Invoke-Command -VMName $VmName -Credential $cred -ScriptBlock {
    Write-Host "Inside VM: Checking OpenSSH Server..."
    
    # Check if OpenSSH Server capability exists and install if needed
    $capability = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
    if ($capability -and $capability.State -ne 'Installed') {
        Write-Host "Inside VM: Installing OpenSSH Server..."
        Add-WindowsCapability -Online -Name $capability.Name | Out-Null
    }

    Write-Host "Inside VM: Configuring sshd service..."
    Set-Service -Name sshd -StartupType 'Automatic'
    Start-Service sshd -ErrorAction SilentlyContinue
    
    if ((Get-Service sshd).Status -eq 'Running') {
        Write-Host "Inside VM: OpenSSH Server is running." -ForegroundColor Green
    } else {
        Write-Host "Inside VM: Failed to start OpenSSH Server." -ForegroundColor Red
    }

    Write-Host "Inside VM: Configuring Firewall..."
    $rule = Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
    if (-not $rule) {
        New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -DisplayName "OpenSSH Server (sshd)" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
        Write-Host "Inside VM: Added firewall rule."
    } else {
        Write-Host "Inside VM: Firewall rule already exists."
    }
}

Write-Host "`nSSH configuration complete!" -ForegroundColor Green
