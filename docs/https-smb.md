# HTTPS and SMB extension

Status: live HTTPS exchange and repaired SMB1 negotiation passed on 22 September
2026, including client/server correlation, reporting, regression checks of the
other protocols, and outbound-policy evidence. See [protocol validation](protocol-validation.md).
The earlier clean-handoff experiment covers its recorded SSH/HTTP/Modbus version;
a clean handoff of this extension has not been demonstrated.

## What changes

| Stage | HTTPS | SMB |
| --- | --- | --- |
| Default scan scope | TCP 443 was already scanned | TCP 445 was already scanned |
| Positive selection evidence | Nmap `method=probed`, HTTP service, `tunnel=ssl` | Separate `smb-protocols` probe returns recognized dialects |
| Container recipe | Dionaea listener 443/TCP | Dionaea listener 445/TCP |
| Default Kubernetes Service port | 443 | 445 |
| External destination | Allocated HTTPS NodePort on the selected node | Allocated SMB NodePort on the selected node |
| Recorded service identity | SQLite protocol `httpd`, transport `tls` | SQLite protocol `smbd`, transport `tcp` |

The planner still requires supported, consistent evidence. Open ports with an
unresolved identity, conflicting observations, or no supported mapping can cause
`review_required` and stop preparation. Merely finding open 443 or 445 is not
sufficient. An incoming connection does not trigger scanning or deployment.

HTTP, HTTPS and SMB can be selected independently or together in one Dionaea
container, with optional Cowrie SSH. Container listeners remain fixed by the
recipe. Service ports can be configured independently from observed target ports;
they must be unique within the release. Nonstandard discovery ports must be
explicitly added to `tcp_ports`; SMB ports also need `smb_probe_ports`.

SMB probing uses one host and one TCP port per scan, passing `smbport` explicitly.
This matters because Nmap reports `smb-protocols` as host-level evidence. The
profiler only attributes it to that explicitly recorded endpoint.

## Image and protocol limits

The extension retains the existing pinned Dionaea image and state layout. It
publishes the selected listeners through Kubernetes; it does not install a new
Dionaea build, inject certificates, change the image's internal service config,
or disable all unselected internal listeners. SMB-selected charts now apply the
[source-checked SMB1 field-name repair](smb1-repair.md) through an init container
and read-only module mount. A Service port declaration cannot make a missing
application listener appear.

Upstream Dionaea documents HTTP and HTTPS listeners and self-signed certificate
generation, plus an SMB service. Those documents do not prove the exact pinned
container works. The recorded lab checks verified TLS 1.3 and repaired SMB1
negotiation with matching server records. The HTTPS certificate fingerprint changed
between the earlier test and the post-upgrade regression; certificate persistence
is not established. On another installation, verify the actual behavior. Do not claim SMB2/SMB3
emulation because discovery recognizes an SMB2/SMB3 target. A limited SMB1
emulator is not a modern Windows file-server replica.

After installation or upgrade, a passive runtime gate checks that the requested
NodePort mappings exist, external traffic policy is Local, one pod is Ready, and
each selected IPv4 listener is bound on the pod. It retries readiness/listener
absence for up to 90 seconds by default; malformed responses and incorrect
mappings fail immediately. Persistent missing listeners fail the run.
The check reads the shared pod network namespace, not process ownership, and
does not prove TLS handshake or SMB negotiation. Failure after Helm may leave a
release installed/upgraded; inspect evidence before recovery. No automatic
destructive rollback is performed.

## First live step: inspect the existing image

On the controller hosting the existing `workflow-mixed` release:

```bash
(
set -euo pipefail
umask 077
export KUBECONFIG="$HOME/.kube/thesis-k3s.yaml"
PROJECT="$HOME/thesis/integrated-system"
mkdir -p "$HOME/thesis/runs"
CHECK=$(mktemp -d "$HOME/thesis/runs/dionaea-capabilities-XXXXXXXX")
python3 "$PROJECT/inspect_dionaea_runtime.py" \
  --release workflow-mixed --namespace honeypots \
  --output "$CHECK/runtime.json" \
  2>&1 | tee "$CHECK/console.log"
echo "Evidence: $CHECK"
)
```

Substitute the actual release name on another controller. This reads image
identity, IPv4 listeners and aggregate database metadata. It sends no test
connections and does not expose ports or read TLS private keys. Inspect whether
443 and 445 are bound and whether the image matches the expected pin. A missing
listener requires image/configuration work before live acceptance.

## Staged live acceptance

1. Preserve the existing workspace and evidence. Use a fresh workspace with new
   release names and dedicated empty state/log roots. New `init` operations copy
   the expanded catalog, deployment mappings and SMB probe configuration.
2. Provide an authorized HTTPS discovery target. Start with HTTPS alongside the
   original HTTP/SSH/Modbus targets. The target should permit Nmap to identify
   HTTP inside TLS; generic TLS alone is insufficient.
3. Run `check`, then `run --mode prepare`. Inspect discovery XML, reconciled plan,
   requests and rendered Services. HTTPS should appear separately from HTTP.
   The actual HoneyChart generation, Helm lint, and server dry run happen here.
4. Run `run --mode install` in that fresh workspace. Read live NodePorts; do not
   reuse example port numbers. Confirm the saved runtime gate and source paths.
5. From another lab VM, perform a TLS handshake followed by an HTTP request to
   the HTTPS NodePort. For this controlled self-signed test, explicitly permit
   the untrusted certificate and record its fingerprint, TLS version/cipher,
   response, UTC time, source IP/port and destination IP/NodePort. Match the
   connection to an `httpd/tls` SQLite record and HTTPS report entry. A valid HTTP
   404 inside TLS is acceptable. A plain TCP connection is insufficient.
6. Add an authorized SMB discovery target and run preparation again. A
   successful dialect probe must select SMB. With Dionaea already present, use
   the compatible upgrade path and verify existing database identity/state is
   retained. Validate the actual supported honeypot dialect from another VM.
   Record protocol negotiation and match the source endpoint/time to an
   `smbd/tcp` SQLite record and SMB report entry. No file upload or exploit is
   required. Do not weaken a real SMB server to make the emulator test pass.
7. Recheck HTTP, SSH and Modbus, then outbound policy enforcement. Confirm the
   expected selected-protocol counts; do not count Nmap's multiple probe
   connections as one connection. Assign controlled-test labels only after
   correlating exact records with independent client evidence.
8. Preserve the revision/diff, configs, image IDs, charts, client/server evidence,
   reports and runtime results. Mark the extension live-validated only after
   these checks pass. TLS certificate persistence across restarts is not claimed
   without an explicit restart/fingerprint test.

The source update alone does not change existing workspace copies, active
releases, storage or timers. Existing reports without `mixed.protocols` keep their
legacy source-wide scope. New generated reporting configs explicitly select
`ssh`, `http`, `https`, and/or `smb` according to prepared requests. Source IDs and
event IDs retain their existing format.

## Offline validation

```bash
python3 -W always::ResourceWarning -m unittest discover -s tests -v
git diff --check
```

The protocol tests cover TLS evidence versus port guesses, positive SMB dialect
evidence and endpoint attribution, conflict handling, explicit scanner arguments,
all fifteen mixed-protocol selections, listener checks, SQLite identity, selected
report counts and legacy reporting. They use fixtures and fake Kubernetes
responses. They do not pull containers, run Nmap on a network, execute Helm or
replace live acceptance.

References: [Dionaea HTTP/HTTPS](https://dionaea.readthedocs.io/en/latest/service/http.html),
[Dionaea SMB](https://dionaea.readthedocs.io/en/latest/service/smb.html),
[Nmap smb-protocols](https://nmap.org/nsedoc/scripts/smb-protocols.html),
[Nmap XML service evidence](https://nmap.org/book/nmap-dtd.html).
