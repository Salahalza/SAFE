$ErrorActionPreference = 'Stop'

# .NET 4.8
Write-Host "Downloading and installing .NET 4.8..."
Invoke-WebRequest -Uri "https://download.visualstudio.microsoft.com/download/pr/014120d7-d689-4305-befd-3cb711108212/0fd66638cde16859462a6243a4629a50/ndp48-x86-x64-allos-enu.exe" -OutFile "C:\ndp48.exe" -UseBasicParsing
Start-Process -FilePath "C:\ndp48.exe" -ArgumentList "/q /norestart" -Wait

# VC++ 2013
Write-Host "Downloading and installing VC++ 2013..."
Invoke-WebRequest -Uri "https://aka.ms/highdpimfc2013x64enu" -OutFile "C:\vcredist_x64.exe" -UseBasicParsing
Start-Process -FilePath "C:\vcredist_x64.exe" -ArgumentList "/install /quiet /norestart" -Wait

# UCMA 4.0
Write-Host "Downloading and installing UCMA 4.0..."
Invoke-WebRequest -Uri "https://download.microsoft.com/download/2/C/4/2C47A5C1-A1F3-4843-B9FE-84C0CB3265D2/UcmaRuntimeSetup.exe" -OutFile "C:\UcmaRuntimeSetup.exe" -UseBasicParsing
Start-Process -FilePath "C:\UcmaRuntimeSetup.exe" -ArgumentList "/q /norestart" -Wait

# URL Rewrite
Write-Host "Downloading and installing IIS URL Rewrite..."
Invoke-WebRequest -Uri "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi" -OutFile "C:\rewrite.msi" -UseBasicParsing
Start-Process -FilePath "msiexec.exe" -ArgumentList "/i C:\rewrite.msi /qn /norestart" -Wait

Write-Host "All prerequisites installed! Restarting..."
Restart-Computer -Force
