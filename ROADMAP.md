# Roadmap

Ideas for after v0.1, roughly in priority order.

1. `watch` mode: poll every N seconds and print opened/closed ports as they happen.
2. Established connections (`portwatch conns`) with remote address and state.
3. macOS support via `lsof -nP -iTCP -iUDP`.
4. Locale-independent Windows parsing (use PowerShell `Get-NetTCPConnection` as an alternative backend).
5. Allow-list file: mark expected ports and report only the unexpected ones, with a non-zero exit code for CI/cron use.
6. Process details: full executable path and command line, owner user.
7. Well-known service names for common ports (22 ssh, 443 https, ...).
8. CSV output and `--sort` option.
9. `snapshot --append` history and a `log` command to show changes over time.
