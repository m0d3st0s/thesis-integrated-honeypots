import argparse
import ipaddress
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from device_profile import host_evidence, describe


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
        if required not in (None, "modbus-discover", "smb-protocols"):
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


def canonical_service(service):
    name = service.get('name', 'unknown')
    tunnel = service.get('tunnel')
    if tunnel:
        return 'https' if name in ('http', 'https') and tunnel == 'ssl' else 'unsupported-tunnel'
    if name == 'https':
        return 'https-without-tls-evidence'
    return {'microsoft-ds': 'smb', 'netbios-ssn': 'smb'}.get(name, name)


def smb_dialects(host):
    # smb-protocols is a HOST script. Its result must only be attributed to the
    # single endpoint explicitly requested by our separate smbport probe.
    # Nmap versions use both dotted and colon-separated dialect labels.
    # Normalize only known wire dialects; retain the raw script as evidence.
    aliases = {
        '2:0:2': '2.0.2', '2:1:0': '2.1', '3:0:0': '3.0',
        '3:0:2': '3.0.2', '3:1:1': '3.1.1',
    }
    values = []
    for script in host.findall("./hostscript/script[@id='smb-protocols']"):
        for element in script.findall("./table[@key='dialects']/elem"):
            value = (element.text or '').strip()
            value = aliases.get(value, value)
            if value in ('2.0.2', '2.1', '3.0', '3.0.2', '3.1.1') or value.startswith('NT LM 0.12 (SMBv1)'):
                values.append(value)
    return sorted(set(values))


def profile_scan(scan_path, catalog_path, *, smb_probe_port=None):
    rules = load_catalog(catalog_path)
    root = ET.parse(scan_path).getroot()
    if root.tag != "nmaprun":
        raise ValueError("Input is not an Nmap XML report.")
    finished = root.find("./runstats/finished")
    if finished is None or finished.get("exit") != "success":
        raise ValueError("Scan did not finish successfully.")
    if smb_probe_port is not None:
        if type(smb_probe_port) is not int or not 1 <= smb_probe_port <= 65535:
            raise ValueError('Invalid explicit SMB probe port.')
        hosts = root.findall('host')
        ports = hosts[0].findall('./ports/port') if len(hosts) == 1 else []
        if len(ports) != 1 or ports[0].get('protocol') != 'tcp' or ports[0].get('portid') != str(smb_probe_port):
            raise ValueError('SMB host-script evidence requires exactly one explicit TCP endpoint.')

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
                "service_cpes": [item.text for item in port.findall('./service/cpe') if item.text],
                "scripts": [
                    preserve_element(script)
                    for script in port.findall("script")
                ],
            }
            index = len(observations)
            observations.append(observation)
            if observation["state"] != "open":
                continue

            dialects = smb_dialects(host) if smb_probe_port == number and transport == 'tcp' else []
            name = 'smb' if dialects else canonical_service(service)
            if dialects:
                observation['smb_dialects'] = dialects
                observation['host_scripts'] = [preserve_element(s) for s in host.findall("./hostscript/script[@id='smb-protocols']")]
            rule = rules.get((transport, name))
            reason = None
            if service.get("method") != "probed" and not dialects:
                reason = "Service identity was not confirmed by probing."
            elif service.get("tunnel") and name != 'https':
                reason = "Tunneled services require a separate mapping."
            elif rule is None:
                reason = "No matching protocol rule in the catalog."
            elif (
                rule.get("required_script") == "modbus-discover"
                and not has_modbus_identification(port)
            ):
                reason = "Modbus identification evidence is missing."
            elif rule.get('required_script') == 'smb-protocols' and not dialects:
                reason = 'SMB dialect negotiation evidence is missing.'

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
        identity = host_evidence(host)
        devices.append({
            "ip": ip,
            "host_evidence": identity,
            "device_profile": describe([{"source_index": 0, "evidence": identity}], observations),
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
