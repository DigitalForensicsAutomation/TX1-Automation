# TX1-Automation
PowerShell Automation: robust script utilizing TX1

TX1Orchestrator.psm1 — full module: session helpers, imaging control, transfer, verification, logging, service-install helpers (NSSM + scheduled task fallback).

TX1Orchestrator.Launcher.ps1 — launcher script for NSSM / scheduled task.

README.md — install & security notes.




The script below provides:

Credential handling via Windows Credential Manager (Get-Credential fallback)

TX1 session login (captures cookie + CSRF token)

Polling GET /api/devices to detect new drives

Start imaging with a templated JSON payload (example)

Poll job status

Download report(s)

Transfer files to SMB or SFTP (Posh-SSH optional)

Verify hashes

Logging and retries

Important: You must adapt \$Tx1ApiBase endpoints to whatever your TX1's API exposes. Use browser DevTools to capture exact endpoints and payload structure if requests fail.
