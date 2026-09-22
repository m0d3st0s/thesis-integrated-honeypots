# User workflow validation — 22 September 2026

Environment: thesis-repro, Ubuntu 24.04.5, Linux amd64, user researcher.
Prerequisites were already installed and configured.

## Verified

- All 18 offline tests passed without resource warnings.
- Workspace initialization and prerequisite checks passed.
- One `honeypotctl.py run --mode install` command completed discovery,
  profiling, selection, chart preparation, fresh installation, reporting
  configuration generation, and immediate reporting.
- Both selected releases passed runtime checks.
- External HTTP, SSH-banner, and Modbus Read Coils tests succeeded.
- A subsequent CLI report contained one HTTP connection, one SSH connection,
  and one Modbus logged start. These remained unclassified with empty labels.
- The workspace-specific timer was installed and enabled.
- Manual execution of its service returned success and exit status zero,
  reporting the correct previous UTC day.

- Live CLI upgrade passed for both installed releases, revision 1 to 2.
  Cowrie's checked SSH fingerprint remained unchanged; Dionaea integrity
  remained ok with one connection row; Conpot remained writable at 969 bytes.
  Reporting configuration and source identities remained unchanged.
  Evidence: runs/run-d6gvygok and runs/upgrade-verification-d3OqYvbC.

## Evidence

Paths below are relative to ~/thesis/user-workflow unless stated otherwise.

- Integrated installation: runs/run-azlzqn95
- Report after protocol tests: reports/configured-report-naje3mg7
- Scheduling/manual service check: runs/schedule-check-Vp6ogpJt
- Manual service report: reports/configured-report-o596_hac
- Timer: honeypot-report-3422e0c16060.timer
- Client transcript on thesis-target:
  /home/mod/thesis/runs/workflow-protocol-check-iJqUbHiq/protocol-check.txt

## Pending and limitations

- First automatic timer execution remains unverified.
- A clean handoff using only shipped instructions remains unverified.

- Protocol responses and report counts were observed; this entry does not
  claim a new detailed per-record client/server correlation.
- This test does not establish compatibility with all Linux distributions,
  architectures, Kubernetes environments, or network layouts.
