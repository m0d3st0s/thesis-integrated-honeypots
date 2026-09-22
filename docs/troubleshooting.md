# Troubleshooting

Use the printed evidence path first. A workspace run saves `workflow.json`,
`prerequisites.json`, `prepare.log`, `deployment.log` and `report.log` as those
stages are reached. Underlying discovery, preparation, deployment and report
folders contain detailed manifests. Preserve the failing run before attempting
recovery. Configuration or transient network errors do not imply a need to reinstall.

## Clone and prerequisite setup

| Symptom | Meaning and next action |
| --- | --- |
| GitHub asks for credentials | Check the repository URL and visibility. The handoff clone succeeded anonymously after publication. Private repositories require an account with access. |
| `destination path ... already exists` | Inspect the directory and its Git status; do not delete an existing checkout to clear the error. |
| Detached HEAD at the recorded commit | Expected when pinning a validation revision. Create a separate development branch before making source changes. |
| npm offers a new major version | Informational. Keep recorded versions during exact reproduction; test upgrades separately. |
| Checksum mismatch or unavailable pinned download | Stop before installing. Preserve the response/error and investigate the recorded artifact/version; do not bypass verification. |
| HoneyChart root is unavailable | Start `npm start` in the reconstructed checkout, inspect its terminal, and verify the configured bind address/port. Restart it after reboot in the foreground setup. |
| HTTP 200 but chart generation fails | Root reachability does not prove build compatibility. Check the pinned source, patch, lockfile, Helm version and preparation log. |

Official GitHub authentication guidance: [troubleshooting clone errors](https://docs.github.com/en/repositories/creating-and-managing-repositories/troubleshooting-cloning-errors).
For HTTPS Git authentication, use a supported credential method such as a personal
access token rather than an account password; never put tokens in report evidence.

## Kubernetes startup and access

`nodes "..." not found` immediately after install means readiness was checked
before registration. Wait for the node to exist, then for `Ready`. A one-second-old
Ready node can still have no system pods or role label. Wait for deployment
creation and rollout as shown in the [setup guide](prerequisites.md).

For unresolved startup problems:

```bash
sudo systemctl status k3s --no-pager
sudo journalctl -u k3s -n 80 --no-pager
```

In the tested K3s build, the kubectl wrapper repeatedly printed:

```text
open /etc/rancher/k3s/config.yaml: permission denied
```

That path is the root-owned server configuration, distinct from the user's
`~/.kube/thesis-k3s.yaml`. The recorded commands still accessed the API successfully
using the explicit user kubeconfig. This warning remained unresolved in the tests;
do not describe it as fixed. Judge the command's exit status and actual result.
Do not broaden credential permissions simply to silence a warning. If API access
fails, inspect the selected kubeconfig path/ownership and cluster health separately.

A failed storage-account check reflects the recipe UID/GID restriction. A remote
client check failure reflects the requirement to run on the storage node. These
are current support limits, not reasons to disable the checks.

## Preparation and deployment

The normal Nmap table can guess `shivadiscovery?` on port 1502. The subsequent
positive `modbus-discover` evidence is what supports Modbus selection in the lab.
Verify the simulator is listening if that evidence is missing.

`No deployment performed` appears in preparation and runtime-preflight tools.
It describes that subcommand, not the entire outer install. Look for the outer
`Workflow status: completed`, deployment result and actual Kubernetes resources.

Helm-managed objects can emit `last-applied-configuration` warnings during
`kubectl apply --dry-run=server`. The observed validations passed; those dry runs
do not establish a persisted annotation change. Helm lint's recommended icon
message was also nonfatal.

Use the workspace's actual namespace and release names to inspect workloads:

```bash
kubectl get pods,svc -n honeypots -o wide
kubectl get events -n honeypots --sort-by=.lastTimestamp
helm list -n honeypots --all
```

For `Pending`, `ImagePullBackOff` or crashes, inspect the affected pod with
`kubectl describe pod POD_NAME -n honeypots` and its container logs. Installation
may already have created storage or releases. A second install may correctly
refuse them. Do not delete retained data to make preflight pass.

If a report fails after deployment, check `deployment_status` in `workflow.json`.
A completed deployment with failed reporting should be recovered with `report`
after fixing source/access problems, not by rerunning installation. Failed upgrades
can leave partially changed releases; inspect evidence before another mutation.

## Reports and protocol tests

| Observation | Interpretation |
| --- | --- |
| First immediate report has zero connections | Expected before any client traffic; it is not a traffic-generation test. |
| Previous-day report is empty after today's test | The test lies outside that window. Use an explicit window covering its timestamp. |
| HTTP 404 from the test path | Valid HTTP response; no resource was configured at that path. |
| SSH banner passes | Establishes banner exchange, not successful login or shell emulation. |
| Modbus has three records for one test | Start, payload and disconnect can belong to one session; do not count them as three connections. |
| All events unclassified | Expected with empty controlled-test labels. This is not automatic attack attribution. |
| Selected source missing/malformed | The report fails. Do not replace that result with an empty/zero source. |
| `Cannot assign requested address` in the client script | The source IP is not local to that VM. Run it on the stated external client or adapt its source address. |
| Outbound `Connection refused` | May reflect policy REJECT or another cause. Correlate with policy/firewall counters and a reachable control destination. |

## Timers and evidence

Use `--no-pager` on systemctl/journalctl; press `q` if already inside the pager.
A completed oneshot service becomes inactive. Automatic reporting does not open a
terminal window. Inspect service start/exit timestamps, Result, exit status,
timer LAST/NEXT and the generated report manifest.

A temporary one-date timer can show `NEXT -` after running. Restore its daily
schedule by backing up/removing only the known temporary drop-in and reloading/
restarting the timer. See [timezone and timer operations](reporting-timezones.md).
Generated services depend on the stored project/workspace paths and local source
permissions. Concurrent workspace operations can cause a scheduled report to
fail on its lock; fix the condition and request the missing explicit window.

Persistent timers do not reconstruct all missed daily reports. Archives on the
same VM are not independent backups; copy verified evidence archives elsewhere.
Keep kubeconfigs, private keys and cluster tokens outside shared evidence bundles.
