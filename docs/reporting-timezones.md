# Reporting calendar and timezone

The default remains UTC. New workspaces may use `init --timezone Europe/Athens`.
For an existing workspace, use:

```sh
python3 honeypotctl.py set-timezone --workspace "$HOME/thesis/user-workflow" --timezone Europe/Athens
python3 honeypotctl.py schedule --workspace "$HOME/thesis/user-workflow" --time 00:10 --output /path/to/new/units --install
```

Stop an existing timer before changing its reporting timezone, then regenerate
and install it. Remove any temporary test schedule override and restart the timer.
`set-timezone` backs up workspace and active reporting configuration, preserves
source identities, and does not itself change systemd units.

Scheduling and previous-day reporting use the same IANA timezone. For Athens,
00:10 follows Greek local time, including seasonal changes. A previous day is
bounded by two local midnights, converted to UTC for collection. DST transition
days can contain 23 or 25 hours. Explicit `--since`/`--until` timestamps remain
unchanged. Immediate run reports default to the start of the current local day.

Existing configuration without a timezone continues to use UTC. `--utc-time`
remains a UTC-only compatibility alias; use `--time` for other timezones.
The operating system needs timezone data for the selected zone.

Offline validation: 26 tests passed, including Athens summer/winter boundaries,
23/25-hour days, source identity preservation, and generated timer settings.
Live Athens scheduling still requires validation after applying this update.
The preceding temporary automatic timer test completed successfully on
22 September 2026 at 12:49:16–12:49:18 UTC, with exit status 0.
