# Reporting timezones and scheduled reports

Daily scheduling and calendar-day reporting use the same configured IANA timezone.
The default is `UTC`; `Europe/Athens` follows Greek summer/winter time automatically.
A fixed UTC offset is not a replacement for a timezone with seasonal transitions.

## Calendar semantics

| Operation | Window |
| --- | --- |
| Immediate report after install/upgrade | Current configured local midnight through collection initiation, unless `run --since` overrides the start |
| `report --previous-day` | Previous local midnight through current local midnight |
| `report --since ... --until ...` | Exact supplied offset-aware timestamps; timezone setting does not reinterpret them |

Collectors display normalized UTC boundaries; the start is inclusive and end
exclusive. For a report scheduled at **23 September 2026, 00:10 Europe/Athens**, the
previous Greek day spans `2026-09-21T21:00:00Z` to `2026-09-22T21:00:00Z`.
The 10-minute delay places the scheduled run after the calendar boundary; it does
not prove all delayed/rotated evidence is available or guarantee full coverage.

The implementation converts each local midnight to UTC separately. Greek DST
transition days can therefore contain 23 or 25 hours. Missing `timezone` in an
older workspace/reporting configuration continues to mean UTC. The OS must have
timezone data; unavailable/invalid zones are rejected.

## Install an optional daily schedule

This requires an installed workspace with active `reporting.json`, systemd,
`systemd-analyze`, and sudo access. Restore your paths if using a new terminal:

```bash
export PROJECT="$HOME/thesis/integrated-system"
export WORKSPACE="$HOME/thesis/honeypot-workspace"
```

For a new workspace, choose `init --timezone Europe/Athens` during initialization.
To change an existing workspace, use the change procedure below first.

```bash
(
set -euo pipefail
CHECK=$(mktemp -d "$WORKSPACE/runs/schedule-XXXXXXXX")
python3 "$PROJECT/honeypotctl.py" schedule --workspace "$WORKSPACE" \
  --time 00:10 --output "$CHECK/units" --install
)
```

Omit `--install` for generation/validation only. Output must be a new directory;
`mktemp` creates a parent, and the generator creates its `units` child.
Use `--time` for any configured timezone. The old `--utc-time` alias is accepted
only for a UTC reporting configuration, so it cannot silently mean local time.

The generated unit name includes the workspace identity. Find it without guessing:

```bash
UNIT=$(python3 - "$WORKSPACE/workspace.json" <<'PY'
import json, sys
from pathlib import Path
print("honeypot-report-" + json.loads(Path(sys.argv[1]).read_text())["identity"][:12])
PY
)
systemctl cat "$UNIT.service" "$UNIT.timer" --no-pager
systemctl list-timers --all --full "$UNIT.timer" --no-pager
```

The final service `ExecStart` should call `honeypotctl.py report --workspace ...
--previous-day`, and the timer should contain, for this example,
`OnCalendar=*-*-* 00:10:00 Europe/Athens`. The wrapper first prints the underlying
standalone generator's intermediate units, then rewrites/validates the service
and optionally installs it. Its intermediate “No system service ... installed”
message precedes the wrapper's `Timer installed` message; inspect the final units.

The service uses the generating user's account, HOME, project path and Python
executable. Keep those paths available. It shares the workspace lock, and a
concurrent workspace operation makes reporting fail visibly rather than race.
Direct legacy report scripts do not share this lock.

## Verify execution

A manual service run verifies service configuration, not automatic triggering:

```bash
sudo systemctl start "$UNIT.service"
systemctl show "$UNIT.service" -p Result -p ExecMainStatus \
  -p ExecMainStartTimestamp -p ExecMainExitTimestamp --no-pager
sudo journalctl --utc -u "$UNIT.service" --since today --no-pager
```

To verify automatic activation, leave the VM running through the scheduled time,
then inspect `list-timers` LAST plus the service timestamps, journal and generated
report manifest. Do not manually start the service during that observation window.
Use an appropriate explicit journal time range if the last run was yesterday.
A successful oneshot service normally becomes `inactive` after finishing.
There is no terminal popup; the journal and saved report show what happened.

`Persistent=true` permits catch-up after downtime, including possible activation
when enabling the timer. It does not produce one report for every missed day.
Reports inspect evidence present at collection time. The timer collects reports
only; it does not run discovery, upgrades, traffic tests, or classification.
HoneyChart and the external target VMs are not required to report existing data.

## Change an existing workspace timezone

First identify `UNIT` as above and preserve any execution evidence you need.
Stop its timer before changing calendar semantics:

```bash
(
set -euo pipefail
CHECK=$(mktemp -d "$WORKSPACE/runs/timezone-schedule-XXXXXXXX")
systemctl cat "$UNIT.service" "$UNIT.timer" --no-pager > "$CHECK/previous-units.txt"
sudo systemctl stop "$UNIT.timer"
python3 "$PROJECT/honeypotctl.py" set-timezone \
  --workspace "$WORKSPACE" --timezone Europe/Athens
python3 "$PROJECT/honeypotctl.py" schedule --workspace "$WORKSPACE" \
  --time 00:10 --output "$CHECK/units" --install
sudo systemctl restart "$UNIT.timer"
systemctl cat "$UNIT.timer" --no-pager
systemctl list-timers --all --full "$UNIT.timer" --no-pager
)
```

`set-timezone` backs up workspace/reporting configuration and preserves source
identities. It does not change installed timers itself. It may also be used before
the first installation; scheduling still requires active reporting configuration.
A separately running report retains the window it was already given.

Existing systemd drop-ins can override generated units. Inspect `systemctl cat`
for them. Back up and remove only your known temporary test override, then run
`sudo systemctl daemon-reload` and restart the timer. Do not indiscriminately
remove unrelated overrides. A date-specific `OnCalendar` test has no next date
after firing, so `NEXT -` is expected until the recurring schedule is restored.

## Recorded status

On `thesis-repro`, the temporary ten-minute timer automatically ran at
**2026-09-22 12:49:16 UTC**, completing at **12:49:18 UTC** with exit status 0.
It reported the previous UTC day; zero counts were expected for that window.

The same workspace was subsequently set to `Europe/Athens`. The installed timer
had no temporary override and showed the next activation at **23 September 2026,
00:10 EEST**. Its first activation under that daily Athens schedule has not yet
been supplied as evidence. Do not describe that pending execution as completed.
The fresh handoff run did verify an immediate report beginning at Greek midnight.

26 offline tests passed after the timezone update, including summer/winter
boundaries, 23/25-hour days, source identity preservation and rendered timezone
settings. See [workflow validation](workflow-validation.md) and
[handoff acceptance](handoff-acceptance.md) for the distinct experiments.
