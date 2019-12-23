$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';

# Install Chocolatey
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Globally Auto confirm every action
choco feature enable -n allowGlobalConfirmation

# Install all required dependencies with choco
choco install c:\Windows\Temp\packages.config

# Make `refreshenv` available right away, by defining the $env:ChocolateyInstall
# variable and importing the Chocolatey profile module.
# Note: Using `. $PROFILE` instead *may* work, but isn't guaranteed to.
$env:ChocolateyInstall = Convert-Path "$((Get-Command choco).Path)\..\.."
Import-Module "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"

# Reload environment variables
refreshenv

# Enable prepared transactions in PostgreSQL
$Env:PGPASSWORD='mysecretpassword'; 'ALTER SYSTEM SET max_prepared_transactions = 100;' | psql -Upostgres

# Install Python packages
python -m pip install setuptools wheel
python -m pip install grpcio_tools pysha3 iroha==0.0.5.4 lxml
