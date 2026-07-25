# ─────────────────────────────────────────────────────────────────────
# AEGIS audit tamper-evidence demo (threat model T-13)
# Shows: a clean chain verifies, a tampered chain visibly breaks.
# Run with the gateway running locally and a platform_admin token in $env:AEGIS_TOKEN
# ─────────────────────────────────────────────────────────────────────

$headers = @{ Authorization = "Bearer $env:AEGIS_TOKEN" }

Write-Host "`n1. Verifying a clean chain..." -ForegroundColor Cyan
Invoke-RestMethod -Uri http://localhost:8000/v1/audit/verify -Headers $headers | ConvertTo-Json

Write-Host "`n2. Tampering with audit record #2 directly in the database..." -ForegroundColor Yellow
docker compose -f services/gateway/docker-compose.yml exec -T postgres `
  psql -U aegis -d aegis -c "UPDATE audit_log SET payload = '{\"prompt_chars\": 999999}'::jsonb WHERE sequence = 2;"

Write-Host "`n3. Re-verifying — the chain should now report a break..." -ForegroundColor Cyan
Invoke-RestMethod -Uri http://localhost:8000/v1/audit/verify -Headers $headers | ConvertTo-Json
