$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';

# Install Chocolatey
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Globally Auto confirm every action
choco feature enable -n allowGlobalConfirmation

# Install all required dependencies with choco
choco install c:\Windows\Temp\packages.config