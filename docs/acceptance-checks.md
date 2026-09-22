# Installation acceptance checks

These checks exercise a deployed installation; they do not run as part of the
normal reporting timer. Use your actual addresses/releases/ports. Keep transcripts
and snapshots so conclusions can be checked later. Successful recorded results
are listed in [handoff acceptance](handoff-acceptance.md), not assumed for your run.

## Target checklist

Before discovery, the recorded lab used:

| Target | Services needed for the three-recipe test |
| --- | --- |
| `192.168.77.20` | SSH 22 and HTTP 80; also the external test client |
| `192.168.77.21` | SSH 22 and simulated Modbus 1502 |

On the existing lab's first target, `systemctl is-active ssh nginx` should show
both active. On the second, check `systemctl is-active ssh` and
`sudo ss -ltnp 'sport = :1502'`. If no simulator is running, the **pre-existing lab**
starts it with `cd ~/thesis/ics-simulator` followed by
`./.venv/bin/python modbus_target.py`. Leave that process running.

The integration repository does not supply/install that target simulator or the
target machines. A new user needs their own authorized services; for a complete
three-recipe test they need a suitable Modbus target as well. Do not scan the
original/reproduction controllers as targets. If services are intentionally absent,
expect a smaller selection rather than treating missing recipes as a failed test.

## Run and inspect

Follow `init`, `check` and `run --mode install` in the [user guide](user-guide.md).
Require outer workflow status `completed`, successful deployment/runtime results,
and ready workloads. An empty immediate report before traffic is expected.

On the controller, read actual NodePorts:

```bash
export KUBECONFIG="$HOME/.kube/thesis-k3s.yaml"
kubectl get pods,svc -n honeypots \
  -l 'app.kubernetes.io/instance in (handoff-mixed,handoff-modbus)'
```

Replace the release names for your workspace. Record a baseline report before
sending traffic if there may already be events. A baseline is a snapshot, not an
assumption of no background activity.

## External protocol exchange

Run the following on the external client, not the controller. Replace the five
values at the top with its actual source IP, the controller's reachable address
and **current** NodePorts. The displayed port numbers are historical handoff
values and may differ after any new installation.

```bash
(
set -euo pipefail
umask 077
mkdir -p "$HOME/thesis/runs"
CHECK=$(mktemp -d "$HOME/thesis/runs/protocol-check-XXXXXXXX")
python3 -u - "$CHECK/client.json" <<'PY' 2>&1 | tee "$CHECK/client.txt"
import json, socket, struct, sys
from datetime import datetime, timezone
from pathlib import Path
host, source = "192.168.77.12", "192.168.77.20"
ports = {"http": 32415, "ssh": 31811, "modbus": 30101}
records = []
def require(condition, message):
    if not condition:
        raise RuntimeError(message)
def exact(connection, count):
    data = bytearray()
    while len(data) < count:
        part = connection.recv(count - len(data))
        require(bool(part), "Incomplete response")
        data.extend(part)
    return bytes(data)
def line(connection):
    data = bytearray()
    while len(data) < 4096:
        data.extend(exact(connection, 1))
        if data.endswith(b"\n"):
            return bytes(data).rstrip(b"\r\n")
    raise RuntimeError("Response line too long")
for service, port in ports.items():
    record = {"service": service, "started_at": datetime.now(timezone.utc).isoformat()}
    with socket.create_connection((host, port), timeout=5, source_address=(source, 0)) as connection:
        connection.settimeout(5)
        record.update(source=list(connection.getsockname()), destination=list(connection.getpeername()))
        if service == "http":
            connection.sendall(("GET /thesis-acceptance HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n").encode("ascii"))
            response = line(connection)
            require(response.startswith(b"HTTP/1."), repr(response))
            record["response"] = response.decode(errors="replace")
        elif service == "ssh":
            response = line(connection)
            require(response.startswith(b"SSH-2.0-"), repr(response))
            record["response"] = response.decode(errors="replace")
        else:
            request = bytes.fromhex("000100000006010100010008")
            connection.sendall(request)
            header = exact(connection, 7)
            require(struct.unpack(">HHHB", header) == (1, 0, 4, 1), "Unexpected Modbus header")
            payload = exact(connection, 3)
            require(payload[:2] == b"\x01\x01", "Unexpected Read Coils reply")
            record.update(request_hex=request.hex(), response_hex=(header + payload).hex(), response_payload_hex=payload.hex())
    records.append(record)
    print("PASS:", json.dumps(record))
Path(sys.argv[1]).write_text(json.dumps({"tests": records}, indent=2) + "\n")
print("Client JSON:", sys.argv[1])
PY
echo "Client evidence: $CHECK"
)
```

HTTP 404 is a valid response to an unconfigured path. The SSH test checks a banner,
not login/shell behavior. Modbus checks the requested transaction/unit/function,
framing and byte count; the returned coil byte may vary.

## Report and correlate

Copy `client.json` and `client.txt` from the printed client directory to a new
controller evidence directory, for example using scp or shared host storage.
Verify SSH host identity if prompted. Keep credentials out of the copied files.
Set `CLIENT_JSON` to the copied JSON's absolute path; this is the file from the
new test above, not the historical transcript-only file.

On the controller, restore PROJECT/WORKSPACE and set the client path:

```bash
export PROJECT="$HOME/thesis/integrated-system"
export WORKSPACE="$HOME/thesis/honeypot-workspace"
# Replace this value with the location where you copied client.json.
export CLIENT_JSON="$HOME/thesis/client-evidence/client.json"
```

Collect a new report and correlate within its saved snapshots. The five-minute
margin accommodates small clock differences; separately verify clocks if records
fall outside it. Source-port/session/payload correlation is not a clock-latency
measurement.

```bash
(
set -euo pipefail
umask 077
CHECK=$(mktemp -d "$WORKSPACE/runs/protocol-evidence-XXXXXXXX")
cp "$CLIENT_JSON" "$CHECK/client.json"
SINCE=$(python3 - "$CHECK/client.json" <<'PY'
import json, sys
from datetime import datetime, timedelta
from pathlib import Path
records = json.loads(Path(sys.argv[1]).read_text())["tests"]
print((min(datetime.fromisoformat(x["started_at"]) for x in records) - timedelta(minutes=5)).isoformat())
PY
)
python3 "$PROJECT/honeypotctl.py" report --workspace "$WORKSPACE" \
  --since "$SINCE" --until "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --output "$CHECK/collected"
python3 - "$CHECK" <<'PY' | tee "$CHECK/correlation.txt"
import hashlib, json, sys
from pathlib import Path
root = Path(sys.argv[1])
report = root / "collected/report"
client = root / "client.json"
mixed_file = report / "ssh-http/window-feed.json"
conpot_file = report / "modbus/conpot-evidence.json"
mixed = json.loads(mixed_file.read_text())["connections"]
conpot = json.loads(conpot_file.read_text())["events"]
matched = {}
def one(items, label):
    if len(items) != 1:
        raise SystemExit(label + ": expected one match, got " + str(len(items)))
    return items[0]
for test in json.loads(client.read_text())["tests"]:
    service = test["service"]
    ip, port = test["source"]
    if service in ("http", "ssh"):
        event = one([x for x in mixed if x["service"] == service and x["remote_ip"] == ip
                     and x["remote_port"] == port and x["count_as_inbound_connection"]], service)
        matched[service] = event
    else:
        records = [x for x in conpot if x["remote_ip"] == ip and x["remote_port"] == port]
        event = one([x for x in records if x["is_connection_start_record"]], "Modbus start")
        payload = one([x for x in records if x["request_hex"] == test["request_hex"]
                       and x["response_hex"] == test["response_payload_hex"]], "Modbus payload")
        for key in ("deployment", "session_id", "local_ip", "local_port"):
            if event[key] != payload[key]:
                raise SystemExit("Modbus start/payload mismatch: " + key)
        matched["modbus_start"], matched["modbus_payload"] = event, payload
    print("PASS:", service, event["event_id"])
result = {"status": "matched", "records": matched, "source_sha256": {
    str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (client, mixed_file, conpot_file)}}
(root / "matched-events.json").write_text(json.dumps(result, indent=2) + "\n")
PY
echo "Server correlation evidence: $CHECK"
)
```

This example expects all three sources. Adapt selection for an intentionally
smaller deployment. With a zero baseline and no extra traffic, expect HTTP 1,
SSH 1 and Conpot 1 start/1 payload/3 records. Repeated tests or other traffic can
increase counts; match individual events rather than assuming totals prove identity.
The procedure does not modify classification labels. Unclassified is expected.

## Outbound enforcement

Use a known reachable target in the authorized lab. Keep it running, confirm the
controller can reach it before/after probes, and inspect policy plus firewall
counters around pod-originated attempts. A connection error alone is insufficient
attribution. Never remove the deny policy merely to make a test succeed.

The tested K3s environment exposes policy rules through `sudo iptables-save -c`.
For another CNI/backend use its own enforcement evidence; absence of these exact
chain names is not proof that a policy is ineffective.

The following uses the handoff release names and `.20:80`; adapt them. It probes
Dionaea in the mixed pod and Conpot in the other pod. It does not separately probe
Cowrie's process or every possible destination/protocol.

```bash
(
set -euo pipefail
umask 077
export KUBECONFIG="$HOME/.kube/thesis-k3s.yaml"
CHECK=$(mktemp -d "$WORKSPACE/runs/egress-check-XXXXXXXX")
sudo -v
python3 -u - "$CHECK" <<'PY' 2>&1 | tee "$CHECK/check.log"
import json, re, socket, subprocess, sys
from pathlib import Path
folder = Path(sys.argv[1])
def capture(command, name):
    result = subprocess.run(command, capture_output=True, text=True)
    (folder / name).write_text(result.stdout)
    (folder / (name + ".stderr")).write_text(result.stderr)
    if result.returncode:
        raise SystemExit("Command failed; inspect " + str(folder / (name + ".stderr")))
    return result.stdout
def host_check():
    with socket.create_connection(("192.168.77.20", 80), timeout=5):
        print("PASS: target HTTP port reachable from host")
def counters(text):
    return {rule:int(n) for n,rule in re.findall(r"(?m)^\[(\d+):\d+\] (-A KUBE-.*)$", text)}
pods = json.loads(capture(["kubectl","get","pods","-n","honeypots","-o","json"],"pods.json"))
capture(["kubectl","get","networkpolicy","-n","honeypots","-o","json"],"policies.json")
probe = '''
import json, socket
results=[]
for attempt in range(3):
    try:
        with socket.create_connection(("192.168.77.20",80),timeout=5):
            results.append({"connected":True})
    except OSError as exc:
        results.append({"connected":False,"error":str(exc)})
print(json.dumps(results))
'''
for release, container in [("handoff-mixed","dionaea"),("handoff-modbus","conpot")]:
    selected=[p for p in pods["items"] if p["metadata"].get("labels",{}).get("app.kubernetes.io/instance")==release
              and not p["metadata"].get("deletionTimestamp")]
    if len(selected)!=1:
        raise SystemExit("Expected exactly one pod for " + release)
    pod=selected[0]
    name,address=pod["metadata"]["name"],pod["status"]["podIP"]
    print("Testing:", name, container, address)
    host_check()
    before=capture(["sudo","iptables-save","-c"],release+"-before.rules")
    output=capture(["kubectl","exec","-n","honeypots",name,"-c",container,"--","python3","-c",probe],release+"-probe.json")
    after=capture(["sudo","iptables-save","-c"],release+"-after.rules")
    results=json.loads(output)
    print(results)
    if any(x["connected"] for x in results):
        raise SystemExit("STOP: unexpected outbound connection succeeded")
    host_check()
    old=counters(before)
    for rule,count in counters(after).items():
        if rule in old and count>old[rule] and (name in rule or "deny-outbound" in rule or "-s "+address+"/32" in rule):
            print("+"+str(count-old[rule])+" packets:",rule)
print("Review counter evidence before attributing the observed failures to policy.")
PY
echo "Outbound evidence: $CHECK"
)
```

The recorded handoff produced three failed attempts per pod and +3 in each pod's
policy path and REJECT rule, with the host control reachable before and after.
Use your own counter output; do not print a policy-enforcement PASS solely because
no socket connection succeeded. Save both full rulesets to detect changed/reset
rules or concurrent traffic before interpreting a delta.

## Optional follow-up and archive

A compatible upgrade can be tested with `run --mode upgrade`, comparing saved
before/after checks and report identities. An automatic timer requires observing
an actual scheduled activation, not just manually starting its service. These
operations were tested separately on `thesis-repro`; they need not be repeatedly
run to substantiate the handoff install/protocol/report result. See
[validation scope](workflow-validation.md) and [timer operations](reporting-timezones.md).

After operations finish, record source status and archive evidence. Substitute
your actual workspace/setup evidence names below. Keep active database/log roots
out of this simple tar recipe; report snapshots are already inside the workspace.
Pause scheduled reporting during archival if it could modify those evidence files,
then restore its timer. Keep user kubeconfig/private keys outside shared archives.

```bash
(
set -euo pipefail
umask 077
mkdir -p "$HOME/thesis/archives"
ARCHIVE=$(mktemp -d "$HOME/thesis/archives/acceptance-XXXXXXXX")
git -C "$PROJECT" rev-parse HEAD > "$ARCHIVE/source-commit.txt"
git -C "$PROJECT" status --short > "$ARCHIVE/source-status.txt"
git -C "$PROJECT" diff --binary HEAD > "$ARCHIVE/source.patch"
tar -czf "$ARCHIVE/evidence.tar.gz" -C "$HOME/thesis" \
  setup-evidence honeypot-workspace
gzip -t "$ARCHIVE/evidence.tar.gz"
tar -tzf "$ARCHIVE/evidence.tar.gz" > "$ARCHIVE/contents.txt"
(
cd "$ARCHIVE"
sha256sum evidence.tar.gz > SHA256SUMS
sha256sum --check SHA256SUMS
)
echo "Copy this directory off the VM: $ARCHIVE"
)
```

If client evidence was saved outside those directories, copy it into the workspace
before archival. A valid checksum proves archive integrity against that checksum;
it does not independently validate every claimed experiment or prove an off-VM
backup exists. Record any extra guidance/fixes used during the exercise, and label
an operator-assisted run as guided rather than an independent docs-only handoff.
