# ---------- SAFE DEMO BLOCK (replace the old client-start through render section) ----------
# Ensure cert exists
if (-not (Test-Path 'certs/server.crt')) {
  ./scripts/generate_cert.ps1
}

# Start server (background, redirected to logs)
$python = 'python'
$art = 'artifacts'
New-Item -ItemType Directory -Force -Path $art, "$art/logs" | Out-Null
Start-Process -FilePath $python -ArgumentList 'src/server.py --host 127.0.0.1 --port 8443' `
  -RedirectStandardOutput "$art/logs/server.log" `
  -RedirectStandardError "$art/logs/server.err" -WindowStyle Minimized
Start-Sleep -Seconds 1

# Add demo users (idempotent)
& $python src/server.py --add-user alice Password1! | Out-Null
& $python src/server.py --add-user bob   Password1! | Out-Null

# Get fingerprint once
$fp = & $python scripts/print_fingerprint.py
Write-Host "Fingerprint: $fp"

# Start clients with redirection (these keep the log files open)
$cli1 = "src/client_cli.py --username alice --password Password1! --pin $fp"
$cli2 = "src/client_cli.py --username bob   --password Password1! --pin $fp"

$ps1 = Start-Process -PassThru -FilePath $python -ArgumentList $cli1 `
  -RedirectStandardOutput "$art/logs/client1.log" `
  -RedirectStandardError "$art/logs/client1.err" -WindowStyle Minimized

Start-Sleep -Milliseconds 500

$ps2 = Start-Process -PassThru -FilePath $python -ArgumentList $cli2 `
  -RedirectStandardOutput "$art/logs/client2.log" `
  -RedirectStandardError "$art/logs/client2.err" -WindowStyle Minimized

# Wait to let "Auth OK" appear in logs, then STOP clients to release the file handles
Start-Sleep -Seconds 3
if ($ps1 -and !$ps1.HasExited) { Stop-Process -Id $ps1.Id -Force -ErrorAction SilentlyContinue }
if ($ps2 -and !$ps2.HasExited) { Stop-Process -Id $ps2.Id -Force -ErrorAction SilentlyContinue }

# Give Windows a tick to flush + release
Start-Sleep -Seconds 1

# Now logs are free; append our scripted lines
Add-Content "$art/logs/client1.log" "> Hello from Alice"
Add-Content "$art/logs/client2.log" "> Hi Alice, this is Bob"

# Render logs -> images
& $python scripts/render_logs_to_images.py

Write-Host "Demo complete. Screenshots at artifacts/*.png"
# ---------- END SAFE DEMO BLOCK ----------