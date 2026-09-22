# Earlier staged fresh-VM reproduction

This page preserves the earlier experiment on **22 September 2026**. For a new
installation, use [prerequisites](prerequisites.md) and the
[workspace user guide](user-guide.md). For the current public-checkout exercise,
see [handoff acceptance](handoff-acceptance.md).

## What this experiment established

A separate VM reproduced discovery, preparation, first installation, external
protocol exchanges, matched server records, controlled-test reporting and manual
systemd reporting. It used the lower-level staged prepare/install commands before
the new workspace CLI. Do not attribute a single-command CLI run or later timer
results to this earlier run.

| Item | Recorded value |
| --- | --- |
| Integration code | `6ac744f53aa78fa667a84db672c83228349d9b2a` |
| HoneyChart upstream | `6522d81d71a38df86de9da409a83acbbcd3a267e` |
| VM / user | `thesis-repro` / `researcher` |
| OS / kernel | Ubuntu 24.04.5 (upgraded from 24.04.2) / `7.0.0-31-generic` |
| Architecture / allocation | x86-64 / 2 CPUs, about 6 GiB RAM, 40 GB disk |
| Python / Nmap | 3.12.3 / 7.94SVN |
| Node / npm | v24.21.0 / 11.19.0 |
| Helm / K3s | v3.22.0+g144ca65 / v1.36.4+k3s1 |

These are observed versions, not a compatibility range. Host prerequisites were
installed manually. The installer bootstrapped honeypot storage/releases, not the
OS, Kubernetes or the existing controlled target simulator.

## Network, source reconstruction and cluster

NAT `enp0s3` supplied internet access. Internal `thesis-lab` on `enp0s8` used
`192.168.77.11/24`; the original controller `.10` and scanner `.11` were excluded.
Target `.20` provided SSH/nginx HTTP; `.21` provided SSH and simulated Modbus on
1502. The target simulator already existed at `~/thesis/ics-simulator` on `.21`.
Nmap's general guess `shivadiscovery?` was followed by a positive `modbus-discover`
probe identifying the lab simulator.

HoneyChart's recorded commit, patch and lockfile were reconstructed; `npm ci`
completed without changing the lockfile. `host.json` bound to `127.0.0.1:8081`.
The project independently ran K3s with this configuration:

```yaml
node-name: thesis-repro
node-ip: 192.168.77.11
advertise-address: 192.168.77.11
flannel-iface: enp0s8
write-kubeconfig-mode: "0600"
disable:
  - traefik
  - servicelb
```

A user-owned mode-0600 kubeconfig was copied to `~/.kube/thesis-k3s.yaml`.
Namespace `honeypots` and all-pod `deny-outbound` policy were created. The initial
node lookup preceded registration; a later check showed Ready with all three
system pods running. See the current setup guide for the registration wait.

## Staged commands and configuration

Separate configuration files in `~/thesis/reproduction-config` set scanner `.11`,
exclusions `.10/.11`, node hostname `thesis-repro`, absolute image-pin location,
namespace `honeypots`, state root `/var/lib/thesis-honeypots` and log root
`/var/log/honeypots`. Ports were 22, 80, 443, 445, 502 and 1502; Modbus probe ports
502 and 1502. Releases were `auto-mixed-01` and `ics-modbus-01`.

The historical invocation pattern was:

```bash
# Historical pattern: use a new output directory and adapted configurations.
python3 "$PROJECT/run_system.py" \
  --scan-config "$CONFIG/scan.json" \
  --catalog "$PROJECT/config/service-catalog.json" \
  --deployment-config "$CONFIG/deployment.json" \
  --runtime-config "$CONFIG/runtime.json" \
  --output "$RUN/system" --mode prepare

python3 "$PROJECT/install_prepared.py" "$RUN/system/prepared" \
  --output "$RUN/installation" --install
```

The recorded main evidence root was
`/home/researcher/thesis/runs/reproduction-Dsp4WrfQ`; prepared evidence was under
`system/prepared`. The commands above illustrate the lower-level interface;
new users should use `honeypotctl.py` to derive reporting automatically.

Both charts passed lint, rendering and server-side dry-run checks. Initialization
and installation completed, with the mixed pod 2/2 and Modbus pod 1/1 Ready.
Observed NodePorts were HTTP 31061, SSH 31038 and Modbus 31039, all on `.11`.
These are historical values; query current Services for any new test.

## Protocol tests and labels

Client `.20` contacted controller `.11` at approximately **09:52:20 UTC**:

| Protocol | Client source port | Server evidence |
| --- | --- | --- |
| HTTP | 37825 | Dionaea connection 1, HTTP 404 response |
| SSH | 35647 | Cowrie session `1492d8637347`, SSH banner |
| Modbus | 38323 | Session `3f13c967-1f90-4179-a3be-fe13d67c6482` |

Modbus request `000100000006010100010008` matched full client reply
`000100000004010101e4` and server payload `0101e4`. Its three server records were
start, payload and disconnect, not three connections. Client/server records were
correlated before assigning controlled-test labels.

The reproduction reporting configuration used database identity
`thesis-repro-Dsp4WrfQ-dionaea-initial`, independent Conpot source identity and
separate empty label files. A baseline showed HTTP 1, SSH 1 and one Conpot logged
start unclassified. After exact labels were added, the classified report contained
HTTP 1 controlled, SSH 1 controlled, and Modbus 1 controlled logged start,
1 payload record, 3 total records, zero unclassified starts and no missing labels.
SSH/HTTP and Modbus metrics remained separate.

## Outbound and scheduling checks

The host reached target `.20:80`. All three containers' outbound attempts returned
connection errors. An additional Conpot test made three attempts; its policy path
and pod REJECT counters each increased by three, supporting policy rejection for
that tested Conpot TCP traffic. This experiment did not separately attribute the
mixed pod failures through per-pod counters. The later handoff did so for both pods.

Generated `thesis-daily-report` units passed validation and were installed. Manual
service execution succeeded with exit 0, reporting the previous UTC day. This
historical timer's first automatic execution was not recorded. The later verified
automatic execution used the distinct workspace-specific timer documented in
[workflow validation](workflow-validation.md).

## Evidence locations

Relative to `/home/researcher/thesis/runs/reproduction-Dsp4WrfQ`:

- Discovery/preparation: `system/`.
- Server correlation: `protocol-evidence-ZwgTdKDB`.
- Baseline and classified reports: `reporting/baseline`, `reporting/classified`.
- Supporting label evidence: `reporting/label-evidence`.
- Generated units: `reporting/systemd-units`.
- Manual service evidence: `reporting/systemd-check-MdUQnbUn`.
- Source/version record: `reproducibility-record-q5DTtH0z`.
- Copied client evidence: `client-evidence/thesis-target-protocol-check.txt`.

Other locations:

- Original client transcript on `.20`:
  `/home/mod/thesis/runs/repro-protocol-check-iv3mnvSV/protocol-check.txt`.
- Counter test: `/home/researcher/thesis/runs/egress-counter-check-8ccxhifw`.
- Checkpoint: `/home/researcher/thesis/archives/reproduction-checkpoint-P479Yvvd`.

The checkpoint contained the main run and counter evidence, passed gzip and
SHA-256 verification and was reported as 132 KB. These are operator-held paths,
not files included in this source repository.

## Limitations carried forward

Preparation/preflight “No deployment performed” messages describe their own
subcommands. Root-owned K3s config warnings and Helm dry-run annotation warnings
were nonfatal in the observed successful runs; they were not claimed to be fixed.
The Modbus target was simulated. SSH checks exercised banners, not logins.
Snapshots do not establish complete time-window coverage; labels and source IDs
belong to this experiment. The run does not establish unattended provisioning,
arbitrary Linux/architecture support, or independent documentation usability.
