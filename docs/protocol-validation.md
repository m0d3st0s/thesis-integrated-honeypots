# HTTPS and SMB lab validation — 22 September 2026

## Scope and provenance

These results come from operator-supplied client transcripts, saved server
snapshots/reports and firewall-counter output on `thesis-repro` (192.168.77.11),
with external client `thesis-target` (192.168.77.20). The workspace was
`~/thesis/protocol-workspace`, with releases `protocol-mixed` and
`protocol-modbus`. Results apply to the tested patched source and pinned images.
The final feature commit must be recorded when the source is committed; no
commit identifier is inferred here. This is guided live acceptance, not a fresh
independent handoff of the extension or a claim of universal Linux compatibility.

## Results

| Check | Recorded result |
| --- | --- |
| HTTPS discovery | Nmap identified HTTP inside TLS on target TCP 8443; selected Dionaea HTTPS |
| SMB discovery | Dedicated TCP 445 dialect probe identified the Samba target's SMB2/3 dialects |
| Preparation and deployment | Final retry `runs/run-qetfwjcb` completed after dialect, SMB1 and startup fixes |
| Initial HTTPS test | TLS 1.3 and HTTP 404; client source port 49041 matched Dionaea connection 1 |
| Repaired SMB1 test | NT LM 0.12 negotiated; source ports 41280 and 41286 matched Dionaea connections 4 and 5 |
| HTTP regression | Source port 42529; HTTP 200; matched Dionaea connection 6 |
| HTTPS regression | Source port 55763; TLS 1.3 and HTTP 200; matched Dionaea connection 7 |
| SSH regression | Source port 50157; SSH-2.0 banner; matched Cowrie session e0c4a91b123f |
| Modbus regression | Source port 44235; Read Coils request and response matched Conpot start and payload records |
| Outbound check | Three attempts from each tested pod to 192.168.77.20:80 failed; per-pod policy and REJECT counters each increased by three |

The VM could reach the outbound-test destination immediately before and after
each pod's probes. The tested pods were `protocol-mixed-59c9cc4948-l76dc`
(10.42.0.22, Dionaea container) and `protocol-modbus-5c8689df85-kqwn5`
(10.42.0.20, Conpot container). This supports rejection of those tested flows;
it is not an exhaustive test of all destinations, protocols or network paths.

At regression time the node's NodePorts were HTTP 30900, HTTPS 30660, SMB 30126,
SSH 32757 and Modbus 32450. These are recorded observations, not portable defaults.
Regression client timestamps span 2026-09-22T19:41:56.763331+00:00 through
2026-09-22T19:41:56.836106+00:00. Matching allowed a two-second timestamp tolerance
and also required the exact source endpoint, service and internal listener.
Modbus additionally required the same session and exact request/response payload.

## Failures retained and limits

- The first SMB plan failed because recognized Nmap colon-form dialect strings
  needed normalization. The profiler was corrected rather than bypassing review.
- The original pinned SMB1 handler raised `KeyError: OemDomainName`. The guarded
  [SMB1 repair](smb1-repair.md) corrects two field-name references on each pod start.
- The immediate listener check raced application startup. The bounded readiness
  wait was added, and the final workflow retry completed. Failed runs remain evidence.
- SMB1 negotiation is validated. SMB2/3 emulation, authentication and file
  operations are not validated. Discovery of SMB2/3 does not mean dialect fidelity.
  The two labeled probe connections are not two demonstrated successful negotiations.
- HTTPS certificate verification was explicitly disabled only in the lab probes.
  The certificate SHA-256 changed from
  `bd73cb38af0c916cbcda12b826b10bf469d6bf77057a15bf73b1d1efb17716eb` to
  `3db1640954bef5267d11631ca2e2b1fdf456d67bdf73f73f3363819c80ba8c17`.
  Stable certificate identity across upgrades/restarts is not established.
- Reports count incoming starts, not attacks. Conpot logged starts remain a
  separate metric, and its timestamps describe session creation.
- Earlier failed SMB probes remain unclassified unless separately correlated and
  labeled. The four regression records were correlated successfully; their saved
  initial report predates any regression-label update. Preserve both reports.
- The test suite reached 56 passing offline tests after the startup fix. Offline
  tests complement these live observations; they do not replace them.

## Evidence locations

Paths below are relative to `~/thesis/protocol-workspace` on thesis-repro unless
an absolute path is given. They describe retained local evidence, not Git files.

| Evidence | Location |
| --- | --- |
| HTTPS client/server match and controlled label | `runs/https-correlation-7evP4sFY` |
| SMB failure diagnosis | `runs/smb-runtime-diagnosis-0bM8suJY` |
| Repair startup and passive runtime check | `runs/smb1-startup-check-gKoxnPdP` |
| Successful final workflow | `runs/run-qetfwjcb` |
| Repaired SMB client/server correlation and classified report | `runs/smb-correlation-IIXKdWLL` |
| Four-protocol client transcript on target | `/home/mod/thesis/runs/protocol-regression-yE0rH3BL` |
| Four-protocol copied client evidence, report and matches | `runs/regression-correlation-m8KRE63z` |
| Final policy and REJECT counters | `runs/final-egress-check-2OwXS6EI` |

Archive these with the final source revision/diff and runtime/configuration
records. Label helpers back up prior label files and preserve the matched IDs;
a later classified report must be distinguished from the original snapshot.
