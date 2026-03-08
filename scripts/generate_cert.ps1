# Generates self-signed RSA certificate into certs/ using OpenSSL
$ErrorActionPreference = 'Stop'
mkdir certs -Force | Out-Null
if (Get-Command openssl -ErrorAction SilentlyContinue) {
  openssl req -x509 -newkey rsa:2048 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=SecureChatLocal"
  Write-Host "Self-signed certificate generated in certs/"
} else {
  Write-Host "OpenSSL not found. Install via Chocolatey: choco install openssl --pre -y"
  Write-Host "Or install Git for Windows (includes openssl) and re-run this script."
}
