# NodePort and MetalLB LoadBalancer

The CLI defaults to NodePort. New workspaces can select LoadBalancer with an
existing MetalLB IPv4 Layer 2 installation, a named pool and one explicitly
reserved address per release. Mixed Cowrie/Dionaea protocols share one address;
Conpot uses a different address. This is service exposure, not a full replica of
an observed device and not high availability for node-local persistent storage.

## Reservation comes first

A silent ping, a free-looking ARP table or an unused address is not a reservation.
Reserve the addresses in the network's allocation records, exclude them from
DHCP allocation and other static assignments, and coordinate with whoever
manages the subnet. In VirtualBox identify the actual network attachment and check its DHCP
configuration on the host, plus any DHCP server running inside a guest.
The validated lab used the Internal Network `thesis-lab`, not host-only networking. Do not use node, target, gateway,
network or broadcast addresses. Never bind these addresses manually to the
VM interface; MetalLB announces them for the Services.

The checks can detect visible node/Service conflicts and pool membership. They
cannot prove that a DHCP server or an offline machine will not use an address.
The examples below deliberately use variables rather than guessed free lab IPs.

## Cluster prerequisites

Install a pinned, compatible MetalLB release using its official installation
instructions and record its version. The tool does not install a load-balancer
controller. On K3s disable the built-in ServiceLB controller (`servicelb`) on
all server nodes before using MetalLB. Preserve the existing K3s configuration;
do not overwrite it with an example file. Cluster changes and restarts should
be completed and verified separately from workspace installation.

Create an IPAddressPool containing only the reserved addresses, preferably with
`autoAssign: false`, and an L2Advertisement which explicitly lists this pool:

```yaml
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: honeypot-pool
  namespace: metallb-system
spec:
  autoAssign: false
  addresses:
    - REPLACE_WITH_RESERVED_MIXED_IP/32
    - REPLACE_WITH_RESERVED_MODBUS_IP/32
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: honeypot-pool
  namespace: metallb-system
spec:
  ipAddressPools:
    - honeypot-pool
```

This is a template, not an apply-ready manifest. The pool must be reachable
through the lab's actual Layer 2 network. Check any advertisement interface/node
restrictions, MetalLB controller/speaker readiness and VM network limitations.
The initial integration requires explicit `ipAddressPools` advertisement names;
selector-only advertisements, BGP, IPv6 and cloud-provider LB configuration are
outside its current checked scope. RBAC must allow reading nodes, Services and
MetalLB pool/advertisement resources for prerequisite checks.

## Create a separate workspace for the first acceptance run

Set these shell variables to your actual configuration before copying the CLI
command: `PROJECT`, `WORKSPACE`, `NETWORK`, `INTERFACE`, `SCANNER_IP`, `NODE`,
`KUBECONFIG`, `STATE_ROOT`, `LOG_ROOT`, `MIXED_IP` and `MODBUS_IP`.
Use new release names, a new workspace and dedicated storage roots, so that the
first LoadBalancer acceptance run has its own evidence and source identities.

```bash
python3 "$PROJECT/honeypotctl.py" init \
  --workspace "$WORKSPACE" \
  --network "$NETWORK" --interface "$INTERFACE" \
  --scanner-ip "$SCANNER_IP" --node-hostname "$NODE" \
  --kubeconfig "$KUBECONFIG" --namespace honeypots \
  --mixed-release lb-mixed --conpot-release lb-modbus \
  --state-root "$STATE_ROOT" --log-root "$LOG_ROOT" \
  --timezone Europe/Athens \
  --service-type LoadBalancer --metallb-pool honeypot-pool \
  --mixed-lb-ip "$MIXED_IP" --conpot-lb-ip "$MODBUS_IP"

python3 "$PROJECT/honeypotctl.py" check --workspace "$WORKSPACE"
python3 "$PROJECT/honeypotctl.py" run --workspace "$WORKSPACE" --mode prepare
```

Also supply `--exclude ADDRESS` for other controller/honeypot hosts in the scan
network. The scanner and LoadBalancer addresses inside the scan network are
automatically excluded at initialization. Later manual configuration changes
must preserve those exclusions. Both releases need distinct reserved addresses
in configuration even if discovery only selects one release. Only selected
releases are deployed; no address is allocated for an absent release.

After reviewing the prepared evidence, the normal `run --mode install` performs
its own fresh discovery/preparation and installation. Subsequent `run --mode
upgrade` runs use the same workspace and identities. The first acceptance test
is on fresh LB releases; migration of an existing live NodePort release and
changes of LB addresses have not been live-validated.

The generated deployment configuration contains:

```json
{
  "service_type": "LoadBalancer",
  "load_balancer": {
    "address_pool": "honeypot-pool",
    "ips": {
      "lb-mixed": "192.0.2.240",
      "lb-modbus": "192.0.2.241"
    }
  }
}
```

These documentation-only IPs are not proposed lab addresses. Other deployment
fields and mappings remain required. Existing NodePort workspaces need no new
configuration. MetalLB options supplied with NodePort are rejected.

## Generated Service and checks

HoneyChart still generates the chart. The LoadBalancer recipe replaces its
Service template with one Service named exactly after the release, avoiding the
upstream numeric name suffix and deprecated `spec.loadBalancerIP`. It requests
the pool and single IPv4 address with `metallb.io/address-pool` and
`metallb.io/loadBalancerIPs` annotations. NodePort templates remain unchanged.

Both modes use `externalTrafficPolicy: Local`. LoadBalancer explicitly keeps
`allocateLoadBalancerNodePorts: true`, so a load-balanced Service also has
NodePorts. This is not an LB-only exposure mode. Kubernetes may also allocate a
health-check NodePort. The expected external client endpoint is the LB address
and Service port, e.g. mixed IP:443 or Modbus IP:502, not the container's internal
port or the node's IP. Actual source-IP preservation must be tested externally.

Install/upgrade checks verify the type, selected mappings, policy, annotations,
assigned address, Ready pod and bound IPv4 listeners for mixed and Conpot
releases. Pending LB assignment fails to pass; it is retried within the runtime
deadline. A wrong assigned address or mapping fails immediately. Helm has its
own deployment wait before this runtime check. Neither check proves external
routing or a successful application exchange. Failed installs/upgrades retain
evidence and may leave resources; do not blindly repeat an install or delete
persistent data to retry.

Reports save `service-exposure.json` beside the source Service snapshot and show
assigned LB addresses and Service ports, while keeping available NodePorts
visible. Counts and controlled-test labels keep their existing meaning. These
are collection-time mappings, not proof that a historical event entered through
a particular LB address. A report can still collect logs when an address is
pending; it must not be used as a deployment-readiness check.

## Validation status and live acceptance

Offline tests cover configuration and conflict rejection, discovery exclusions,
request propagation, assignment waiting/failure, Conpot runtime checks and actual
report collectors with fixture cluster responses. The previous NodePort tests
remain part of the suite. In development, all 85 tests passed. Actual charts
generated by the pinned HoneyChart source plus the bundled compatibility patch
passed Helm 3.19.0 lint/render checks for both recipes in both exposure modes;
rendered selectors matched the pod labels. Those development checks alone do not establish live MetalLB acceptance.
The subsequent live lab results are recorded below.

For a live acceptance run:

1. Record reservations, DHCP exclusions, K3s ServiceLB state, MetalLB version,
   pool/advertisement configuration and readiness.
2. Run a fresh workspace scan-to-install and save its rendered Services. Verify
   the assigned addresses and ports with `kubectl get service -n honeypots`.
3. From a different lab VM, test HTTP, HTTPS/TLS, SSH, SMB1 negotiation and Modbus
   on the LB addresses and Service ports selected by discovery.
4. Correlate client source endpoints, timestamps and applicable request/response
   payloads with the collected server records. Then add controlled-test labels.
5. Verify tested outbound rejection using host reachability and pod firewall
   counter evidence. LoadBalancer exposure does not replace NetworkPolicy.
6. Upgrade and check state/source identities and addresses, then repeat the
   relevant external checks. Archive the evidence and record the tested commit.

References:
- https://metallb.io/installation/
- https://metallb.io/configuration/
- https://metallb.io/usage/
- https://docs.k3s.io/networking/networking-services
- https://kubernetes.io/docs/concepts/services-networking/service/

## Recorded live validation — 14 October 2026

The LoadBalancer changes were tested on thesis-repro, on top of source commit
fe1bc87100be3b7f1392f374b35809334900039b, before committing this feature.
The environment used K3s v1.36.4+k3s1, Helm v3.22.0 and MetalLB v0.16.1,
with K3s ServiceLB disabled.

The operator reserved 192.168.77.240 and 192.168.77.241 exclusively for this
test on VirtualBox Internal Network thesis-lab. The pool used autoAssign:
false; its L2 advertisement selected thesis-repro and interface enp0s8.
These are this lab's allocations, not addresses other users should copy.

A fresh workspace discovered two target hosts, prepared and validated both
charts, installed lb-mixed and lb-modbus, and completed reporting.
The first attempt had found no targets and deployed nothing; the successful
retry followed restoration of target availability and services.

From a separate VM, 192.168.77.20, the following application checks passed:

- 192.168.77.240:80: HTTP 200.
- 192.168.77.240:443: TLS 1.3 and HTTP 200; certificate verification was
  disabled specifically for the controlled honeypot test.
- 192.168.77.240:22: SSH banner.
- 192.168.77.240:445: SMBv1 negotiation; SMB2/3 emulation was not established.
- 192.168.77.241:502: valid Modbus Read Coils response.

Client source IPs, ports and timestamps matched server records. The Modbus
request and response also matched. Explicit labels classified five mixed-service
connection starts, including two SMB probe connections, and one separate
Modbus logged start as controlled tests. No starts remained unclassified in
the acceptance interval, 13:35:00–13:41:09 UTC.

Three outbound TCP attempts to 192.168.77.20:80 from each tested pod failed
while the destination remained reachable from the node. Each pod's REJECT
counter increased by three. This validates that tested egress path, not all
destinations, protocols or possible bypasses.

Both Helm releases upgraded from revision 1 to 2. Reserved addresses, Service
and NodePort mappings, and reporting source identities remained unchanged.
Cowrie's checked SSH fingerprint remained unchanged. Dionaea retained four
connection rows with database integrity ok. Conpot remained writable with
951 log bytes. The classified records remained present in the upgrade report.

External application checks and the egress probe preceded the upgrade.
Post-upgrade checks verified assignment, listeners, mappings and retained state;
a second external application test was not recorded.

Evidence paths below are local to the operator's VM, not repository contents:

- ~/thesis/runs/metallb-install-ozIWPJS5
- ~/thesis/runs/metallb-pool-5aurc9RD
- ~/thesis/loadbalancer-workspace/runs/run-g8_bg9az
- ~/thesis/loadbalancer-workspace/runs/protocol-correlation-Q2Nh7LcH
- ~/thesis/loadbalancer-workspace/runs/classified-validation-So7L4f7u
- ~/thesis/loadbalancer-workspace/runs/egress-check-WcLzIap2
- ~/thesis/loadbalancer-workspace/runs/run-stdq_0o7
- ~/thesis/loadbalancer-workspace/runs/upgrade-check-YVnrCnnt
- ~/thesis/archives/loadbalancer-acceptance-7WYI2jq0

The archive passed gzip, tar-listing and SHA-256 verification. This validation
covers the tested single-node IPv4 Layer 2 lab. It does not establish multi-node
failover, NodePort-to-LoadBalancer migration, changed-address upgrades, BGP,
IPv6, cloud load balancers or clean-machine handoff of this new feature.
