# Prerequisite setup

The application starts after these prerequisites are available. It does not
provision the host OS, Kubernetes or HoneyChart. If your supported environment is
already configured, go to the [user guide](user-guide.md).

## Requirements and tested baseline

| Requirement | Current contract / recorded baseline |
| --- | --- |
| OS and architecture | Linux; pinned recipes currently checked for amd64/x86-64 |
| Python | 3.10+ with SQLite and `zoneinfo`; tested 3.12.3 |
| Discovery | Nmap with `modbus-discover`; tested 7.94SVN |
| Charts | Helm 3; tested 3.22.0 |
| Kubernetes | Compatible kubectl/server; tested standalone K3s v1.36.4+k3s1 |
| HoneyChart | Recorded upstream commit, bundled patch and dependency lockfile |
| Node / npm | Observed 24.21.0 / 11.19.0; a compatibility range has not been established |
| Utilities | Git, Bash, `ip`, sudo, zip/unzip; curl/xz for the setup below |
| Storage | Local to the selected Kubernetes node; reporting account has UID 0 or 1000, or group 1000 |
| Scheduling | Optional systemd and `systemd-analyze`, plus timezone data |

The live VM baseline used 2 CPUs, about 6 GiB RAM and a 40 GB disk. This is a tested
allocation, not a measured minimum. The two fresh-VM exercises used Ubuntu 24.04;
other distributions have no code whitelist but have not been validated here.
The versions below reproduce the recorded experiment; they are not a claim that
these are the newest releases or that all future versions are compatible.

Run as the future reporting user on the storage node. A remote Kubernetes client
alone cannot read its database/log paths. Kubernetes credentials must permit the
namespace resource operations, Helm releases, pod execution and temporary storage
initialization pods used by the workflow. Recipe storage is created with UID/GID
1000 and mode 0750. Do not make credentials/keys world-readable to bypass access
errors; use an account with appropriate access and validate permissions.

## 1. Base packages and repository

For the tested Ubuntu environment:

```bash
sudo apt update
sudo apt install -y git ca-certificates python3 curl xz-utils \
  nmap iproute2 zip unzip tzdata
mkdir -p "$HOME/thesis"
git clone https://github.com/m0d3st0s/thesis-integrated-honeypots.git \
  "$HOME/thesis/integrated-system"
```

For another distribution, install equivalent packages. A public HTTPS clone
normally needs no sign-in. If the checkout directory exists, inspect/reuse it
rather than cloning over or deleting it. The recorded handoff tested integration
commit `efcd26d42efeb483bd4a299948548ba58e628540`; a newer checkout has a different
provenance and must be recorded as such.

Run the following blocks in the same Bash terminal, or restore these variables
when opening another terminal. Keep evidence outside the source checkout:

```bash
export PROJECT="$HOME/thesis/integrated-system"
mkdir -p "$HOME/thesis/setup-evidence"
export EVIDENCE=$(mktemp -d "$HOME/thesis/setup-evidence/setup-XXXXXXXX")
git -C "$PROJECT" rev-parse HEAD | tee "$EVIDENCE/integration-commit.txt"
git -C "$PROJECT" status --short | tee "$EVIDENCE/integration-status.txt"
python3 --version
nmap --version
nmap --script-help modbus-discover
id
```

## 2. Node and npm

If compatible Node/npm are already installed, record their versions and skip
installation. This fresh-host recipe uses the official Linux x64 archive at the
version recorded in `assets/honeychart/manifest.json`. The checksum comparison
checks against the downloaded official checksum file; the locally recorded hash
is not a separate signature-verification claim.

```bash
(
set -euo pipefail
umask 077
test "$(uname -m)" = x86_64
CHECK=$(mktemp -d "$EVIDENCE/node-XXXXXXXX")
NODE_VERSION=$(python3 - "$PROJECT/assets/honeychart/manifest.json" <<'PY'
import json, sys
from pathlib import Path
print(json.loads(Path(sys.argv[1]).read_text())["observed_node_version"])
PY
)
NODE_RELEASE="node-$NODE_VERSION-linux-x64"
for destination in "/opt/$NODE_RELEASE" /usr/local/bin/node /usr/local/bin/npm /usr/local/bin/npx; do
    if [ -e "$destination" ] || [ -L "$destination" ]; then
        echo "Existing destination; inspect before installing: $destination" >&2
        exit 1
    fi
done
cd "$CHECK"
curl --fail --location --retry 2 \
  "https://nodejs.org/dist/$NODE_VERSION/$NODE_RELEASE.tar.xz" \
  --output "$NODE_RELEASE.tar.xz"
curl --fail --location --retry 2 \
  "https://nodejs.org/dist/$NODE_VERSION/SHASUMS256.txt" --output SHASUMS256.txt
python3 - "$NODE_RELEASE.tar.xz" <<'PY'
import hashlib, sys
from pathlib import Path
archive = Path(sys.argv[1])
expected = [line.split()[0] for line in Path("SHASUMS256.txt").read_text().splitlines()
            if len(line.split()) == 2 and line.split()[1] == archive.name]
actual = hashlib.sha256(archive.read_bytes()).hexdigest()
if expected != [actual]:
    raise SystemExit("Checksum mismatch; stopping.")
print("PASS: Node archive matches the published checksum.")
PY
sudo tar --extract --xz --no-same-owner --file "$NODE_RELEASE.tar.xz" --directory /opt
for tool in node npm npx; do
    sudo ln -s "/opt/$NODE_RELEASE/bin/$tool" "/usr/local/bin/$tool"
done
node --version | tee node-version.txt
npm --version | tee npm-version.txt
)
```

Ignore optional npm version-update notices during exact reproduction. Changing
runtime versions is a separate compatibility test.

## 3. Reconstruct and start HoneyChart

The manifest records upstream commit
`6522d81d71a38df86de9da409a83acbbcd3a267e`. The patch removes the development nodemon
dependency and supplies `httpRoute.enabled: false`. `host.json` is configured
separately to bind to loopback. Do not copy a developer's unrecorded checkout.

```bash
(
set -euo pipefail
umask 077
CHECK=$(mktemp -d "$EVIDENCE/honeychart-XXXXXXXX")
python3 -u - "$PROJECT" "$CHECK" <<'PY' 2>&1 | tee "$CHECK/install.log"
import hashlib, json, shutil, subprocess, sys
from pathlib import Path
project, evidence = map(Path, sys.argv[1:])
assets = project / "assets/honeychart"
manifest = json.loads((assets / "manifest.json").read_text())
checkout = Path.home() / "thesis/honeychart"
if checkout.exists():
    raise SystemExit("HoneyChart checkout exists; inspect before continuing.")
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def run(*command):
    subprocess.run(command, check=True)
for name, expected in manifest["files"].items():
    if digest(assets / name) != expected:
        raise SystemExit("Asset mismatch: " + name)
shutil.copy2(assets / "manifest.json", evidence / "manifest.json")
run("git", "clone", manifest["repository"], str(checkout))
run("git", "-C", str(checkout), "checkout", "--detach", manifest["commit"])
patch = str(assets / "compatibility.patch")
run("git", "-C", str(checkout), "apply", "--check", patch)
run("git", "-C", str(checkout), "apply", patch)
lock = checkout / "package-lock.json"
shutil.copy2(assets / "package-lock.json", lock)
expected = digest(lock)
subprocess.run(["npm", "ci", "--no-audit", "--no-fund"], cwd=checkout, check=True)
if digest(lock) != expected:
    raise SystemExit("Installation changed the lockfile.")
shutil.copy2(checkout / "host.json", evidence / "host-original.json")
(checkout / "host.json").write_text(json.dumps({"host":"127.0.0.1","port":"8081"}, indent=2) + "\n")
print("PASS: HoneyChart source, patch and locked dependency installation completed.")
PY
)
```

In a separate terminal, start it and leave the process running:

```bash
cd ~/thesis/honeychart
npm start
```

In the setup terminal:

```bash
curl --fail --silent --show-error --max-time 10 --output /dev/null \
  --write-out 'HoneyChart HTTP status: %{http_code}\n' http://127.0.0.1:8081/
```

HTTP 200 checks reachability. The workflow checks actual chart generation later.
Restart HoneyChart after reboot if using this foreground setup. Reporting alone
does not need it running.

## 4. Helm 3

If a compatible Helm 3 already exists, record its version and skip this block.
The current workflow rejects Helm 4. This example reproduces the tested 3.22.0:

```bash
(
set -euo pipefail
umask 077
test "$(uname -m)" = x86_64
CHECK=$(mktemp -d "$EVIDENCE/helm-XXXXXXXX")
ARCHIVE=helm-v3.22.0-linux-amd64.tar.gz
if [ -e /usr/local/bin/helm ] || [ -L /usr/local/bin/helm ]; then
    echo "Helm destination exists; inspect before continuing." >&2
    exit 1
fi
cd "$CHECK"
curl --fail --location --retry 2 "https://get.helm.sh/$ARCHIVE" --output "$ARCHIVE"
curl --fail --location --retry 2 "https://get.helm.sh/$ARCHIVE.sha256sum" --output "$ARCHIVE.sha256sum"
sha256sum --check "$ARCHIVE.sha256sum" | tee checksum-verification.txt
tar --extract --gzip --no-same-owner --file "$ARCHIVE"
sudo install -m 0755 linux-amd64/helm /usr/local/bin/helm
helm version --short | tee installed-version.txt
)
```

See [Helm 3 installation instructions](https://helm.sh/docs/v3/intro/install/)
and the current [binary-verification guidance](https://helm.sh/docs/intro/install/#verifying-helm-binaries)
for additional verification methods. Keep Helm 3 for this workflow.

## 5. Network and node identity

Configure networking before installing Kubernetes. The handoff VM used VirtualBox
Adapter 1 as NAT for internet access and Adapter 2 as Internal Network `thesis-lab`,
shared with the controlled targets. A typical VM allocation was 2 CPUs, 6 GiB RAM,
40 GB disk. When cloning a clean OS snapshot, generate new MAC addresses and set
a unique hostname/address before joining the lab. Do not clone a running cluster
and treat its retained state as a fresh installation.

The following are **lab example values**. Replace them for your own machine;
reserve an unused address and exclude other controller/honeypot hosts from scans.

```bash
sudo hostnamectl set-hostname thesis-handoff
ip -brief link
nmcli device status
```

In the tested Ubuntu NetworkManager setup, the new interface was `enp0s8` with
profile `Wired connection 1`. Substitute the actual interface/profile shown above:

```bash
sudo nmcli connection modify "Wired connection 1" \
  connection.interface-name enp0s8 \
  ipv4.method manual ipv4.addresses 192.168.77.12/24 \
  ipv4.gateway "" ipv4.dns "" ipv4.never-default yes \
  ipv6.method disabled connection.autoconnect yes
sudo nmcli connection up "Wired connection 1"
ip -4 -brief address
ip -4 route
```

The recorded result was NAT `enp0s3=10.0.2.15/24`, default route via `10.0.2.2`,
and lab `enp0s8=192.168.77.12/24` with no lab default gateway. This example assumes
an isolated IPv4 lab; use your distribution's network tooling for other layouts.

## 6. Standalone K3s example

Existing supported Kubernetes installations can be used if they meet the contract.
This fresh-host example installs a separate K3s server with the recorded version.
Edit the node/address/interface values to match step 5. It stops if existing K3s
state/configuration is found; investigate rather than deleting retained data.

```bash
(
set -euo pipefail
umask 077
CHECK=$(mktemp -d "$EVIDENCE/k3s-XXXXXXXX")
sudo -v
if command -v k3s >/dev/null 2>&1 \
  || sudo test -e /etc/rancher/k3s/config.yaml \
  || sudo test -e /var/lib/rancher/k3s; then
    echo "Existing K3s installation/configuration found; stopping." >&2
    exit 1
fi
cat > "$CHECK/config.yaml" <<'YAML'
node-name: thesis-handoff
node-ip: 192.168.77.12
advertise-address: 192.168.77.12
flannel-iface: enp0s8
write-kubeconfig-mode: "0600"
disable:
  - traefik
  - servicelb
YAML
curl --fail --location --retry 2 https://get.k3s.io --output "$CHECK/install-k3s.sh"
sha256sum "$CHECK/install-k3s.sh" > "$CHECK/install-k3s.sh.sha256"
sudo install -d -m 0755 /etc/rancher/k3s
sudo install -m 0600 "$CHECK/config.yaml" /etc/rancher/k3s/config.yaml
sudo env INSTALL_K3S_VERSION='v1.36.4+k3s1' INSTALL_K3S_EXEC='server' \
  sh "$CHECK/install-k3s.sh" 2>&1 | tee "$CHECK/install.log"
registered=false
for attempt in {1..60}; do
    if sudo k3s kubectl --request-timeout=5s get node thesis-handoff >/dev/null 2>&1; then
        registered=true
        break
    fi
    sleep 3
done
if [ "$registered" != true ]; then
    sudo journalctl -u k3s -n 80 --no-pager
    exit 1
fi
sudo k3s kubectl wait --for=condition=Ready node/thesis-handoff --timeout=180s
sudo k3s kubectl get nodes -o wide | tee "$CHECK/nodes.txt"
sudo k3s kubectl get pods -A | tee "$CHECK/system-pods.txt"
)
```

The installer verifies its downloaded binary. The saved installer hash records
which installer was used; it is not independent authentication of that script.
Do not disable K3s's network-policy controller. See official
[K3s configuration](https://docs.k3s.io/installation/configuration),
[requirements](https://docs.k3s.io/installation/requirements) and
[networking](https://docs.k3s.io/networking/networking-services).

## 7. User access, system readiness, namespace and policy

Configure an explicit user kubeconfig for kubectl and Helm. It is an administrative
credential: do not print it into evidence, commit it, or share it. Copies may need
refreshing when embedded credentials expire; see
[K3s cluster access](https://docs.k3s.io/cluster-access).

```bash
export KUBECONFIG="$HOME/.kube/thesis-k3s.yaml"
(
set -euo pipefail
umask 077
mkdir -p "$HOME/.kube"
chmod 0700 "$HOME/.kube"
if [ -e "$KUBECONFIG" ] || [ -L "$KUBECONFIG" ]; then
    echo "User kubeconfig already exists; inspect before replacing." >&2
    exit 1
fi
sudo install -m 0600 -o "$(id -u)" -g "$(id -g)" \
  /etc/rancher/k3s/k3s.yaml "$KUBECONFIG"
python3 - <<'PY'
from pathlib import Path
path = Path.home() / ".bashrc"
line = 'export KUBECONFIG="$HOME/.kube/thesis-k3s.yaml"'
text = path.read_text() if path.exists() else ""
if line not in text.splitlines():
    with path.open("a") as output:
        output.write("\n" + line + "\n")
PY
)
```

A just-registered node can be Ready before system Deployments appear. Wait for
both resource creation and rollout, rather than repeatedly reinstalling K3s:

```bash
(
set -euo pipefail
registered=false
for attempt in {1..60}; do
    if kubectl --request-timeout=5s get deployments -n kube-system \
      coredns local-path-provisioner metrics-server >/dev/null 2>&1; then
        registered=true
        break
    fi
    sleep 3
done
if [ "$registered" != true ]; then
    kubectl get deployments,pods -A
    exit 1
fi
for component in coredns local-path-provisioner metrics-server; do
    kubectl rollout status "deployment/$component" -n kube-system --timeout=180s
done
kubectl get nodes -o wide
kubectl get pods -A
helm list --all-namespaces
)
```

For the example dedicated namespace, apply the all-pod default-deny outbound
policy before installing honeypots:

```bash
(
set -euo pipefail
umask 077
cat > "$EVIDENCE/namespace-and-policy.yaml" <<'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: honeypots
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-outbound
  namespace: honeypots
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress: []
YAML
kubectl apply -f "$EVIDENCE/namespace-and-policy.yaml"
kubectl get networkpolicy deny-outbound -n honeypots -o yaml \
  > "$EVIDENCE/installed-policy.yaml"
)
```

Use the same namespace in `init`. The workflow checks policy configuration, not
packet-level enforcement; test enforcement after deployment. Kubernetes policies
combine with other applicable policies, so the checker refuses additional egress
allowances. See [NetworkPolicy semantics](https://kubernetes.io/docs/concepts/services-networking/network-policies/).

Prerequisites are now ready. Continue with [workspace initialization](user-guide.md#initialize-a-workspace).
