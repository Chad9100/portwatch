# Roadmap

Ideas for after v0.1, roughly in priority order.

1. `watch` mode: poll every N seconds and print opened/closed ports as they happen.
2. Established connections (`portwatch conns`) with remote address and state.
3. macOS support via `lsof -nP -iTCP -iUDP`.
4. Locale-independent Windows parsing (use PowerShell `Get-NetTCPConnection` as an alternative backend).
5. ~~Allow-list file: mark expected ports and report only the unexpected ones, with a non-zero exit code for CI/cron use.~~ done: `portwatch check`.
6. Process details: full executable path and command line, owner user.
7. ~~Well-known service names for common ports~~ done: `list --services`.
8. ~~CSV output and `--sort` option~~ done: `list --csv`, `list --sort`.
9. ~~`snapshot --append` history and a `log` command to show changes over time.~~ done: `snapshot --append`, `log`.
10. `watch --history FILE`: append to the history on every poll.
11. ~~`log --since DATE` to limit history output.~~ done: `log --since`.
12. `log --until DATE` and `log --last N` to bound the history from the other end.
13. `check --json` summary with a count, and `check --fail-on-missing` for allow-listed ports that are no longer open.
14. `history prune FILE --keep N` to trim old snapshots from a history file.
