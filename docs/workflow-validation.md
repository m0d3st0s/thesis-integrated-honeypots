# Workspace workflow validation

Status recorded from supplied terminal output and saved-evidence paths on
**22 September 2026**. Historical runs below are distinct experiments; a result
on one VM is not evidence that the same operation ran on another.

## Validation matrix

| Capability | Recorded result | Scope |
| --- | --- | --- |
| Offline workflow/report tests | 18 passed after stream cleanup | `thesis-repro`; no live scan/deployment performed by those tests |
| Offline timezone-inclusive suite | 26 passed, no ResourceWarnings shown | `thesis-repro`, timezone update |
| CLI initial installation and report | Passed | `thesis-repro` and fresh `thesis-handoff` |
| External HTTP, SSH-banner, Modbus exchange | Passed | Both environments; detailed new handoff correlation recorded separately |
| Compatible CLI upgrade, revision 1 to 2 | Passed | `thesis-repro` workspace; not repeated on handoff VM |
| Manual workspace service execution | Success, exit 0 | `thesis-repro` |
| Automatic activation with temporary timer | Success, exit 0 | `thesis-repro`, 12:49:16–12:49:18 UTC |
| Daily Athens schedule installation | Validated and next activation inspected | `thesis-repro`; first automatic Athens daily execution still unrecorded |
| Fresh public-checkout exercise | Passed with guidance | `thesis-handoff`, exact integration commit efcd26d |
| Docs-only independent user exercise | Pending | No independent participant recorded |

## Offline coverage

Run from the integration repository:

```bash
python3 -W always::ResourceWarning -m unittest discover -s tests -v
```

The 26 tests cover the seven nonempty reporting-source selections; missing or
malformed selected sources; legacy configuration defaults; workspace identity and
layout checks; locks; prerequisite failure before scanning; simulated install/
upgrade/report failures; preservation after no-target discovery; scheduling's
workspace entry point; and timezone/DST boundaries and configuration preservation.

Collectors are exercised with fixtures and fake Kubernetes metadata; orchestration
uses simulated stage executables. These tests do not pull images, scan the lab,
deploy containers, or prove firewall behavior. The initial stream ResourceWarnings
were corrected before the successful 18-test run and remained absent in the
reported 26-test run.

## Live workspace on thesis-repro

Environment: Ubuntu 24.04.5, Linux amd64, account `researcher`; prerequisites had
already been prepared. Workspace: `/home/researcher/thesis/user-workflow`.
Releases: `workflow-mixed` and `workflow-modbus` in `honeypots`.

A single CLI install command completed discovery through reporting. Both releases
passed runtime checks. External tests produced HTTP 404, the Cowrie SSH banner,
and a valid Modbus Read Coils reply. The next report counted HTTP 1, SSH 1, and
Conpot 1 logged start with one payload record. Empty labels left them unclassified.
This experiment's report counts alone are not a new per-record correlation claim;
the later [handoff experiment](handoff-acceptance.md) performed that correlation.

The compatible upgrade moved both Helm releases from revision 1 to 2:

| Check | Before and after |
| --- | --- |
| Cowrie checked Ed25519 fingerprint | `SHA256:r8+/Th+QC66rVmymbb0GmRYrBycpMlu3DmdlRKPFIDc` |
| Dionaea database integrity / rows | `ok` / 1 row |
| Conpot log writable / size | true / 969 bytes |
| Reporting configuration / source identities | Unchanged in the recorded comparison |

This proves preservation of the checked properties in that upgrade, not arbitrary
state preservation under every possible topology change.

Evidence relative to that workspace unless stated otherwise:

| Evidence | Path |
| --- | --- |
| Integrated installation | `runs/run-azlzqn95` |
| Post-test report | `reports/configured-report-naje3mg7` |
| Upgrade | `runs/run-d6gvygok` |
| Upgrade comparison | `runs/upgrade-verification-d3OqYvbC` |
| Schedule/manual service test | `runs/schedule-check-Vp6ogpJt` |
| Manual service report | `reports/configured-report-o596_hac` |
| Client transcript, on thesis-target | `/home/mod/thesis/runs/workflow-protocol-check-iJqUbHiq/protocol-check.txt` |
| Earlier workspace archive | `/home/researcher/thesis/archives/user-workflow-bIv9gXD9` |

That archive predates the later automatic-timer/timezone checks and is not claimed
to contain them.

## Automatic reporting and timezone follow-up

Unit: `honeypot-report-3422e0c16060.timer` and matching `.service`.
A date-specific override scheduled **22 September 2026 at 12:49:16 UTC**. The
journal showed automatic start at that instant and successful completion at
12:49:18, `Result=success`, `ExecMainStatus=0`. The report covered 21 September UTC,
so zero counts were expected despite test activity on 22 September.

- Temporary-test setup: `runs/timer-ten-minutes-y4dADKBr`.
- Automatic report: `reports/configured-report-dflfu7eq`.
- Timezone configuration backup: `runs/timezone-change-d9us2_1n`.
- Athens installation/evidence: `runs/athens-schedule-MxmpnSh1`, including the saved
  automatic-test journal, installed units, and next-execution listing.
- Previous unit backup: `runs/timer-backup-6ta0e2id`.

The temporary override was removed. The final timer showed
`OnCalendar=*-*-* 00:10:00 Europe/Athens` and next activation **23 September 2026,
00:10 EEST**. Its first automatic execution under that new schedule remains
unrecorded. The [fresh handoff](handoff-acceptance.md) separately verified an
immediate report beginning at Greek midnight.

## Source milestones and remaining claims

| Commit | Milestone |
| --- | --- |
| `c43610e` | Workspace orchestration and selected-source reporting published |
| `3387230` | Successful live upgrade recorded |
| `efcd26d42efeb483bd4a299948548ba58e628540` | Timezone support; exact code revision used for the fresh public handoff |

The handoff used no integration-source fixes and ended with a clean working tree.
Its prerequisites were installed manually with guidance. It establishes the
recorded operating environment, not universal Linux portability or an independent
documentation-only installation. First Athens daily activation remains pending;
further distributions/architectures and physical ICS targets are unvalidated.
