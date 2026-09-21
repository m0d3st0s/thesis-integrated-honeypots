import argparse
import ipaddress
import json
import xml.etree.ElementTree as ET
from pathlib import Path


def preserve_element(element):
    return {
        "tag": element.tag,
        "attributes": dict(element.attrib),
        "text": element.text.strip() if element.text else None,
        "children": [preserve_element(child) for child in element],
    }


def load_catalog(path):
    catalog = json.loads(path.read_text())
    if catalog.get("schema_version") != 1:
        raise ValueError("Unsupported catalog schema.")

    rules = {}
    for rule in catalog["rules"]:
        for field in ("transport", "service", "honeypot"):
            if not isinstance(rule.get(field), str) or not rule[field]:
                raise ValueError("Invalid catalog field: " + field)
        key = (rule["transport"], rule["service"])
        if key in rules:
            raise ValueError("Duplicate catalog rule: " + str(key))
        required = rule.get("required_script")
        if required not in (None, "modbus-discover"):
            raise ValueError("Unsupported script evidence validator.")
        rules[key] = rule
    return rules


def has_modbus_identification(port):
    for script in port.findall("script"):
        if script.get("id") != "modbus-discover":
            continue
        for table in script.findall("table"):
            if not table.get("key", "").startswith("sid "):
                continue
            for item in table.findall("elem"):
                if item.get("key") in (
                    "Slave ID data", "Device identification"
                ) and (item.text or "").strip():
                    return True
    return False


def profile_scan(scan_path, catalog_path):
    rules = load_catalog(catalog_path)
    root = ET.parse(scan_path).getroot()
    if root.tag != "nmaprun":
        raise ValueError("Input is not an Nmap XML report.")
    finished = root.find("./runstats/finished")
    if finished is None or finished.get("exit") != "success":
        raise ValueError("Scan did not finish successfully.")

    devices = []
    seen_addresses = set()
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        address = next(
            (item for item in host.findall("address")
             if item.get("addrtype") in ("ipv4", "ipv6")),
            None,
        )
        if address is None:
            continue
        ip = str(ipaddress.ip_address(address.get("addr")))
        if ip in seen_addresses:
            raise ValueError("Repeated host address: " + ip)
        seen_addresses.add(ip)

        observations = []
        recommendations = []
        unsupported = []
        seen_ports = set()

        for port in host.findall("./ports/port"):
            number = int(port.get("portid"))
            transport = port.get("protocol")
            if not 1 <= number <= 65535:
                raise ValueError("Invalid port number.")
            key = (transport, number)
            if key in seen_ports:
                raise ValueError("Repeated port observation for " + ip)
            seen_ports.add(key)

            state = port.find("state")
            service_element = port.find("service")
            service = (
                dict(service_element.attrib)
                if service_element is not None else {}
            )
            observation = {
                "port": number,
                "transport": transport,
                "state": (
                    state.get("state") if state is not None else "unknown"
                ),
                "service": service,
                "scripts": [
                    preserve_element(script)
                    for script in port.findall("script")
                ],
            }
            index = len(observations)
            observations.append(observation)
            if observation["state"] != "open":
                continue

            name = service.get("name", "unknown")
            rule = rules.get((transport, name))
            reason = None
            if service.get("method") != "probed":
                reason = "Service identity was not confirmed by probing."
            elif service.get("tunnel"):
                reason = "Tunneled services require a separate mapping."
            elif rule is None:
                reason = "No matching protocol rule in the catalog."
            elif (
                rule.get("required_script") == "modbus-discover"
                and not has_modbus_identification(port)
            ):
                reason = "Modbus identification evidence is missing."

            if reason:
                unsupported.append({
                    "observation_index": index,
                    "port": number,
                    "transport": transport,
                    "service": name,
                    "reason": reason,
                })
            else:
                recommendations.append({
                    "observation_index": index,
                    "honeypot": rule["honeypot"],
                    "service": name,
                    "transport": transport,
                    "observed_port": number,
                    "reason": "Confirmed protocol matches the catalog rule.",
                    "fidelity": "Protocol emulation; not an exact device replica.",
                })

        protocols = sorted({r["service"] for r in recommendations})
        devices.append({
            "ip": ip,
            "profile": (
                "+".join(protocols) + "-enabled-host"
                if protocols else "unclassified"
            ),
            "device_type": "undetermined",
            "observations": observations,
            "summarized_port_states": [
                preserve_element(item)
                for item in host.findall("./ports/extraports")
            ],
            "recommendations": recommendations,
            "unsupported_open_services": unsupported,
        })

    return {
        "schema_version": 3,
        "selection_policy": "evidence-based-protocols-v1",
        "source_scan": str(scan_path.resolve()),
        "scan_started": root.get("start"),
        "scan_finished": finished.get("time"),
        "scan_coverage": [
            dict(item.attrib) for item in root.findall("scaninfo")
        ],
        "catalog_rules": list(rules.values()),
        "scope_note": (
            "Only supplied scan evidence is considered. Device identities "
            "are self-reported. Recommendations are not deployment approval."
        ),
        "devices": devices,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan", type=Path)
    parser.add_argument("--catalog", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = profile_scan(args.scan, args.catalog)
    except (OSError, ET.ParseError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"Error: {exc}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
