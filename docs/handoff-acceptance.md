# Fresh-VM handoff acceptance — 22 September 2026

## Result and scope

The public integration repository at commit
`efcd26d42efeb483bd4a299948548ba58e628540` completed a **guided fresh-VM** installation
and scan-to-report run. The final integration working tree was clean. No source
patch was required during the exercise; the documented HoneyChart compatibility
patch was applied to its separate upstream checkout.

This is evidence that the supported workflow runs after manual prerequisite setup
in the recorded environment. It is not an independent docs-only usability test,
a universal Linux/architecture claim, or a validation of physical ICS fidelity.

## Environment

| Item | Observed value |
| --- | --- |
| VM / account | `thesis-handoff` / `mod` |
| OS / architecture | Ubuntu 24.04.2 LTS / x86-64 |
| Kernel | `7.0.0-31-generic` in the Kubernetes node output |
| Resources | 2 CPUs, about 6 GiB RAM, 40 GB root filesystem |
| Network | NAT `enp0s3=10.0.2.15/24`; lab `enp0s8=192.168.77.12/24` |
| Python / Nmap | 3.12.3 / 7.94SVN |
| Node / npm | v24.21.0 / 11.19.0 |
| Helm / K3s | v3.22.0+g144ca65 / v1.36.4+k3s1 |
| HoneyChart commit | `6522d81d71a38df86de9da409a83acbbcd3a267e` |
| Workspace | `/home/mod/thesis/handoff-workspace` |
| Namespace | `honeypots` |
| Storage roots | `/var/lib/thesis-honeypots/handoff`, `/var/log/honeypots/handoff` |
| Timezone | `Europe/Athens` |

The first Git clone requested authentication while the integration repository was
private. After the owner made it public, the clone succeeded with terminal
credential prompting disabled. Node and Helm archives passed published checksum
comparisons. HoneyChart asset checks, patch application, `npm ci` with unchanged
lockfile, and HTTP 200 root check passed.

K3s registered the independent node at `.12`. Its earliest Ready output had no
system resources yet; all three system deployments subsequently rolled out.
The user kubeconfig worked with private permissions. The known root-owned K3s
server-config warning remained nonfatal and unresolved.

## Configuration and integrated run

`init` used release names `handoff-mixed` and `handoff-modbus`, namespace
`honeypots`, and the paths above. Scan scope was `192.168.77.0/24` on `enp0s8`,
excluding controllers `.10`, `.11` and scanner `.12`. TCP ports were
22, 80, 443, 445, 502, 1502; Modbus probe ports 502 and 1502.

All prerequisite checks passed. The controlled targets were:

- `.20` (`thesis-target`): SSH and nginx HTTP; also the external test client.
- `.21` (`thesis-target-2`): SSH and a pre-existing simulated Modbus endpoint on
  TCP 1502. The simulator was a lab prerequisite, not installed by this project.

A single `honeypotctl.py run --mode install` completed discovery, service profiling,
selection, HoneyChart/chart validation, storage initialization, both releases,
runtime checks, reporting configuration generation and immediate reporting.

Run: `handoff-workspace/runs/run-o31b9y8n`.
Console: `handoff-evidence/first-run-3T5fPIsD`.
The initial report had zero interactions, correctly beginning at
`2026-09-21T21:00:00Z` (22 September, 00:00 in Athens). Both pods were fully Ready,
with zero restarts in the recorded post-install listing.

| Release | Pod | Observed NodePorts |
| --- | --- | --- |
| handoff-mixed | `handoff-mixed-ddc5c44d9-kktnd` (2/2) | HTTP 32415, SSH 31811 |
| handoff-modbus | `handoff-modbus-6698cf7b97-qhddc` (1/1) | Modbus 30101 |

These ports and pod names are historical observations, not configuration defaults.

## External responses and server correlation

Client source was `.20`; destination was `.12`. All three exchanges passed at
approximately **15:36:27 UTC**:

| Protocol | Source port | Observed response |
| --- | --- | --- |
| HTTP | 41799 | `HTTP/1.1 404 Not Found` |
| SSH | 48729 | `SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2` |
| Modbus | 37953 | Full response `0001000000040101013b` to request `000100000006010100010008` |

Report `handoff-workspace/reports/configured-report-feeubu7v` completed with HTTP 1,
SSH 1, and Conpot 1 logged start, 1 payload record, 3 records total. All remained
unclassified; no controlled-test labels were added in this handoff exercise.

The copied client transcript was correlated with the saved report evidence:

- HTTP: source `.20:41799`, event
  `dionaea:117ab839355e418f9eb0914771145fbb-handoff-mixed-dionaea:connection:1`,
  server timestamp `2026-09-22T15:36:27.072950+00:00`.
- SSH: source `.20:48729`, event
  `cowrie:handoff-mixed-ddc5c44d9-kktnd:ad5e43944ce9:connect`,
  server timestamp `2026-09-22T15:36:27.085559+00:00`.
- Modbus: source `.20:37953`; one start and one matching payload record had matching
  session/local endpoint metadata. Recorded request matched exactly; response
  payload was `01013b`. Full byte-offset/hash event IDs and matched records are
  preserved in `matched-events.json` under the correlation evidence directory.

HTTP 404 demonstrates a response, not application content fidelity. The SSH test
was a banner exchange, not a login/shell test. Modbus coil data is observed data,
not a fixed expected byte. Separate VM clocks are not a latency measurement.

## Outbound-policy evidence

Target `.20:80` was reachable from the host before and after each pod's test.
Three outbound connection attempts were then made from each of:

- Dionaea in the mixed pod at `10.42.0.6`.
- Conpot in the Modbus pod at `10.42.0.7`.

All attempts returned connection-refused errors. For each pod, counters increased
by three in its `deny-outbound` path and by three in its final policy REJECT rule
(`icmp-port-unreachable`). The named policy logging rule also increased by three
in each measurement. This supports policy rejection of the tested TCP traffic
from both pods. It is not all-destination/all-protocol proof, nor a separate
Cowrie-process probe.

## Evidence index

Paths below are relative to `/home/mod/thesis` on `thesis-handoff` unless stated
otherwise. These operator-held artifacts are not bundled in the Git repository.

| Evidence | Path |
| --- | --- |
| Starting environment | `handoff-evidence/starting-environment.txt` |
| Base packages | `handoff-evidence/base-packages.txt` |
| Node installation | `handoff-evidence/node-install-wgc49jyh` |
| HoneyChart installation | `handoff-evidence/honeychart-install-V30735M0` |
| HoneyChart HTTP check | `handoff-evidence/honeychart-http.txt` |
| Network | `handoff-evidence/network-X9gEhWOi` |
| K3s installation | `handoff-evidence/k3s-install-8cAo2ba4` |
| Cluster bootstrap | `handoff-evidence/cluster-bootstrap-516jjXNd` |
| Workspace init/check | `handoff-evidence/workspace-setup-J2NvA1EO` |
| First run console | `handoff-evidence/first-run-3T5fPIsD` |
| Integrated run | `handoff-workspace/runs/run-o31b9y8n` |
| Correlation and copied client evidence | `handoff-evidence/protocol-correlation-IGZMz24c` |
| Outbound counter evidence | `handoff-evidence/egress-check-U8qfdakN` |
| Original client file, on thesis-target | `/home/mod/thesis/runs/handoff-protocol-check-p9Kz6GZh/protocol-check.txt` |
| Verified archive directory | `archives/handoff-acceptance-NzHJN9an` |

Final provenance was recorded at **2026-09-22 15:49:04 UTC**: the exact integration
commit above and no working-tree changes. The archive contains `handoff-evidence`
and `handoff-workspace`; gzip validation and `sha256sum --check` passed. Its
reported size was 66 MB. The supplied transcript does not include the archive
hash value, so no value is invented here. Copying that archive off the VM was
requested but has not been confirmed in the recorded evidence.

The handoff VM did not repeat upgrade or scheduled-service tests. Those verified
operations belong to the earlier [workflow experiment](workflow-validation.md).
