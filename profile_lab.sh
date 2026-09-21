#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$HOME/thesis/integrated-system"
LAB_NETWORK="192.168.77.0/24"
SCANNER_IP="192.168.77.10"
LAB_INTERFACE="enp0s8"

for command in python3 nmap ip; do
    command -v "$command" >/dev/null || {
        echo "Missing command: $command" >&2
        exit 1
    }
done

# Confirm that the expected lab address is on the expected interface.
ip -j -4 addr show dev "$LAB_INTERFACE" |
python3 -c '
import json
import sys

interfaces = json.load(sys.stdin)
valid = any(
    address.get("local") == "192.168.77.10"
    and address.get("prefixlen") == 24
    for interface in interfaces
    for address in interface.get("addr_info", [])
)
if not valid:
    raise SystemExit("Expected lab interface configuration was not found.")
'

sudo -v
mkdir -p "$HOME/thesis/runs"
if [ "$#" -eq 0 ]; then
    RUN_DIR=$(mktemp -d "$HOME/thesis/runs/lab-profile-XXXXXXXX")
elif [ "$#" -eq 1 ]; then
    RUN_DIR="$1"
    mkdir -- "$RUN_DIR"
else
    echo "Usage: $0 [NEW_OUTPUT_DIRECTORY]" >&2
    exit 1
fi
echo "Run directory: $RUN_DIR"

echo "1. Discovering devices on the internal lab network..."
sudo nmap -sn -n -e "$LAB_INTERFACE" \
    --exclude "$SCANNER_IP" \
    "$LAB_NETWORK" \
    -oX - > "$RUN_DIR/discovery.xml"

echo "2. Building the discovered target list..."
python3 - "$RUN_DIR" <<'PY'
import ipaddress
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

folder = Path(sys.argv[1])
network = ipaddress.ip_network("192.168.77.0/24")
excluded = ipaddress.ip_address("192.168.77.10")
root = ET.parse(folder / "discovery.xml").getroot()

finished = root.find("./runstats/finished")
if finished is None or finished.get("exit") != "success":
    raise SystemExit("Discovery did not finish successfully.")

targets = set()
devices = []

for host in root.findall("host"):
    status = host.find("status")
    if status is None or status.get("state") != "up":
        continue

    address = host.find("address[@addrtype='ipv4']")
    if address is None:
        continue

    ip = ipaddress.ip_address(address.get("addr"))
    if (
        ip not in network
        or ip == excluded
        or ip in (network.network_address, network.broadcast_address)
    ):
        raise SystemExit("Unexpected discovered address: " + str(ip))

    mac = host.find("address[@addrtype='mac']")
    targets.add(ip)
    devices.append({
        "ip": str(ip),
        "discovery_reason": status.get("reason"),
        "mac": mac.get("addr") if mac is not None else None,
        "mac_vendor": mac.get("vendor") if mac is not None else None,
    })

ordered = sorted(targets)
(folder / "targets.txt").write_text(
    "".join(str(ip) + "\n" for ip in ordered)
)

inventory = {
    "schema_version": 1,
    "network": str(network),
    "excluded_ips": [str(excluded)],
    "scan_started": root.get("start"),
    "discovered_device_count": len(ordered),
    "devices": devices,
    "scope_note": (
        "Devices responding to this discovery scan; "
        "not proof that every connected device was found."
    ),
}
(folder / "inventory.json").write_text(
    json.dumps(inventory, indent=2) + "\n"
)

print("Discovered devices:", len(ordered))
for ip in ordered:
    print(" ", ip)
PY

if [ ! -s "$RUN_DIR/targets.txt" ]; then
    echo "No targets discovered. Inventory saved: $RUN_DIR/inventory.json"
    exit 0
fi

echo "3. Identifying services on discovered devices..."
nmap -sT -sV --version-light -n \
    -p 22,80,443,445 \
    -iL "$RUN_DIR/targets.txt" \
    -oX "$RUN_DIR/services.xml"

echo "4. Profiling discovered services..."
python3 "$PROJECT_DIR/profiler_v2.py" "$RUN_DIR/services.xml" \
    > "$RUN_DIR/profile.json"

python3 - "$RUN_DIR" <<'PY'
import json
import sys
from pathlib import Path

folder = Path(sys.argv[1])
inventory = json.loads((folder / "inventory.json").read_text())
profile = json.loads((folder / "profile.json").read_text())

discovered = {device["ip"] for device in inventory["devices"]}
profiled = {device["ip"] for device in profile["devices"]}

if not profiled.issubset(discovered):
    raise SystemExit("Profile contains an address outside the discovered list.")

for device in profile["devices"]:
    print("{}: {}".format(device["ip"], device["profile"]))
    for recommendation in device["recommendations"]:
        print("  {} / port {} -> {}".format(
            recommendation["service"],
            recommendation["observed_port"],
            recommendation["honeypot"],
        ))
    for unsupported in device["unsupported_open_services"]:
        print("  Unmapped: port {} — {}".format(
            unsupported["port"], unsupported["reason"]
        ))

missing = sorted(discovered - profiled)
(folder / "profiling-status.json").write_text(json.dumps({
    "discovered_device_count": len(discovered),
    "profiled_device_count": len(profiled),
    "discovered_but_not_profiled": missing,
}, indent=2) + "\n")

if missing:
    print("Discovered but not profiled:", ", ".join(missing))
PY

echo "Discovery and profiling completed: $RUN_DIR"
