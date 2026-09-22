import argparse
import ipaddress
import json
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from profiler_v3 import load_catalog, profile_scan


def now():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")


def successful_scan(path):
    root = ET.parse(path).getroot()
    finished = root.find("./runstats/finished")
    if (
        root.tag != "nmaprun"
        or finished is None
        or finished.get("exit") != "success"
    ):
        raise ValueError("Incomplete or unsuccessful scan: " + str(path))
    return root


def port_list(value, name, allow_empty=False):
    if not isinstance(value, list) or (not value and not allow_empty):
        raise ValueError(name + " must be a list of ports.")
    if any(type(p) is not int or not 1 <= p <= 65535 for p in value):
        raise ValueError("Invalid port in " + name)
    if len(set(value)) != len(value):
        raise ValueError("Duplicate port in " + name)
    return sorted(value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--catalog", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    folder = None
    manifest = None
    try:
        config = json.loads(args.config.read_text())
        if config.get("schema_version") != 1:
            raise ValueError("Unsupported scan configuration schema.")

        network = ipaddress.IPv4Network(config["network"], strict=True)
        scanner = ipaddress.IPv4Address(config["scanner_ip"])
        interface = config["interface"]
        if not isinstance(interface, str) or not interface:
            raise ValueError("A network interface is required.")
        if scanner not in network:
            raise ValueError("Scanner address is outside the configured network.")

        excluded = {
            ipaddress.IPv4Address(value) for value in config["exclude_ips"]
        }
        excluded.add(scanner)
        if any(ip not in network for ip in excluded):
            raise ValueError("Excluded addresses must be inside the network.")

        ports = port_list(config["tcp_ports"], "tcp_ports")
        modbus_ports = port_list(
            config["modbus_probe_ports"], "modbus_probe_ports", allow_empty=True
        )
        if not set(modbus_ports).issubset(ports):
            raise ValueError("Modbus probe ports must be included in tcp_ports.")
        smb_ports = port_list(config.get('smb_probe_ports', []), 'smb_probe_ports', allow_empty=True)
        if not set(smb_ports).issubset(ports):
            raise ValueError('SMB probe ports must be included in tcp_ports.')
        if set(smb_ports) & set(modbus_ports):
            raise ValueError('SMB and Modbus probe ports must not overlap.')

        load_catalog(args.catalog)
        for command in ("ip", "nmap", "sudo"):
            if shutil.which(command) is None:
                raise ValueError("Missing command: " + command)

        interfaces = json.loads(subprocess.check_output(
            ["ip", "-j", "-4", "addr", "show", "dev", interface], text=True
        ))
        if not any(
            item.get("local") == str(scanner)
            for device in interfaces
            for item in device.get("addr_info", [])
        ):
            raise ValueError("Configured scanner IP is not on this interface.")

        output = args.output.expanduser().resolve()
        output.mkdir(parents=True, exist_ok=False)
        folder = output
        write_json(folder / "scan-config.json", {
            **config,
            "exclude_ips": [str(ip) for ip in sorted(excluded)],
        })
        catalog = folder / "service-catalog.json"
        catalog.write_bytes(args.catalog.read_bytes())

        manifest = {
            "schema_version": 1,
            "started_at": now(),
            "status": "running",
            "commands": [],
            "profiles": [],
            "limitations": [
                "Discovery finds responding devices, not necessarily all devices.",
                "Only configured TCP ports are scanned.",
                "Probe observations are collected at different times.",
                "Separate profiles require evidence reconciliation before planning.",
            ],
        }

        def save():
            write_json(folder / "scan-manifest.json", manifest)

        def run(command):
            record = {"argv": command, "started_at": now()}
            manifest["commands"].append(record)
            save()
            try:
                result = subprocess.run(command, check=True)
                record["returncode"] = result.returncode
            except subprocess.CalledProcessError as exc:
                record["returncode"] = exc.returncode
                raise
            finally:
                record["finished_at"] = now()
                save()

        def save_profile(xml_name, profile_name, kind, port=None):
            result = profile_scan(folder / xml_name, catalog, smb_probe_port=port if kind == 'smb' else None)
            write_json(folder / profile_name, result)
            manifest["profiles"].append({
                "kind": kind,
                "source_xml": xml_name,
                "profile": profile_name,
                **({'port': port} if kind == 'smb' else {}),
            })
            save()

        print("Evidence directory:", folder, flush=True)
        run(["sudo", "-v"])
        run([
            "sudo", "nmap", "-sn", "-n", "-e", interface,
            "--exclude", ",".join(str(ip) for ip in sorted(excluded)),
            str(network), "-oX", str(folder / "discovery.xml"),
        ])

        targets = set()
        root = successful_scan(folder / "discovery.xml")
        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue
            address = host.find("address[@addrtype='ipv4']")
            if address is None:
                continue
            ip = ipaddress.IPv4Address(address.get("addr"))
            if ip not in network or ip in excluded:
                raise ValueError("Unexpected discovered address: " + str(ip))
            targets.add(ip)

        ordered = [str(ip) for ip in sorted(targets)]
        manifest["discovered_targets"] = ordered
        (folder / "targets.txt").write_text(
            "".join(ip + "\n" for ip in ordered)
        )
        print("Discovered devices:", len(ordered), flush=True)

        if ordered:
            run([
                "nmap", "-sT", "-sV", "--version-light", "-Pn", "-n",
                "-p", ",".join(map(str, ports)),
                "-iL", str(folder / "targets.txt"),
                "-oX", str(folder / "services.xml"),
            ])
            root = successful_scan(folder / "services.xml")
            save_profile("services.xml", "services-profile.json", "general")

            candidates = set()
            smb_candidates = set()
            scanned = set()
            for host in root.findall("host"):
                address = host.find("address[@addrtype='ipv4']")
                if address is None:
                    continue
                ip = str(ipaddress.IPv4Address(address.get("addr")))
                if ip not in ordered:
                    raise ValueError("Unexpected service-scan address: " + ip)
                scanned.add(ip)
                for port in host.findall("./ports/port"):
                    state = port.find("state")
                    number = int(port.get("portid"))
                    if (
                        port.get("protocol") == "tcp"
                        and number in modbus_ports
                        and state is not None
                        and state.get("state") == "open"
                    ):
                        candidates.add((ip, number))
                    if (port.get('protocol') == 'tcp' and number in smb_ports
                            and state is not None and state.get('state') == 'open'):
                        smb_candidates.add((ip, number))

            if scanned != set(ordered):
                raise ValueError("Service scan omitted discovered targets.")

            for index, (ip, port) in enumerate(sorted(candidates), 1):
                xml_name = f"modbus-{index:03d}.xml"
                run([
                    "nmap", "-sT", "-Pn", "-n",
                    "-p", str(port),
                    "--script", "+modbus-discover",
                    "--script-timeout", "30s",
                    ip, "-oX", str(folder / xml_name),
                ])
                successful_scan(folder / xml_name)
                save_profile(
                    xml_name, f"modbus-{index:03d}-profile.json", "modbus"
                )

            for index, (ip, port) in enumerate(sorted(smb_candidates), 1):
                xml_name = f'smb-{index:03d}.xml'
                run(['nmap', '-sT', '-Pn', '-n', '-p', str(port),
                     '--script', '+smb-protocols', '--script-args', 'smbport=' + str(port),
                     '--script-timeout', '30s', ip, '-oX', str(folder / xml_name)])
                successful_scan(folder / xml_name)
                save_profile(xml_name, f'smb-{index:03d}-profile.json', 'smb', port=port)

        manifest["status"] = "completed" if ordered else "no_targets"
        manifest["finished_at"] = now()
        save()
        print("Collection status:", manifest["status"])
        print("Evidence saved:", folder)

    except (
        OSError, ValueError, KeyError, TypeError, ET.ParseError,
        subprocess.CalledProcessError
    ) as exc:
        if folder is not None and manifest is not None:
            manifest["status"] = "failed"
            manifest["error"] = str(exc)
            manifest["finished_at"] = now()
            write_json(folder / "scan-manifest.json", manifest)
        parser.exit(1, f"Error: {exc}\n")


if __name__ == "__main__":
    main()
