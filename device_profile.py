"""Descriptive device assessments. Never an input to service selection."""
import re


FAMILIES = {
    'linux': 'linux', 'windows': 'windows', 'microsoft windows': 'windows',
    'freebsd': 'freebsd', 'openbsd': 'openbsd', 'netbsd': 'netbsd',
    'mac os x': 'macos', 'macos': 'macos', 'darwin': 'macos',
    'solaris': 'solaris', 'sunos': 'solaris', 'unix': 'unix',
    'android': 'android',
}
UNIX_FAMILIES = {'linux', 'freebsd', 'openbsd', 'netbsd', 'macos', 'solaris', 'android'}
ROLES = {'ssh': 'ssh_server', 'http': 'web_server', 'https': 'web_server',
         'smb': 'smb_server', 'modbus': 'modbus_endpoint', 'ftp': 'ftp_server',
         'smtp': 'mail_server', 'imap': 'mail_server', 'pop3': 'mail_server',
         'domain': 'dns_server', 'snmp': 'snmp_agent'}


def host_evidence(host):
    """Preserve structured hints; do not interpret vendor names or banner prose."""
    hints = []
    for i, match in enumerate(host.findall('./os/osmatch')):
        for j, cls in enumerate(match.findall('osclass')):
            ref = f'os/osmatch[{i}]/osclass[{j}]'
            if cls.get('osfamily'):
                hints.append(dict(kind='os_fingerprint', value=cls.get('osfamily'),
                                  xml_path=ref, attributes=dict(cls.attrib),
                                  match_attributes=dict(match.attrib)))
            for cpe in cls.findall('cpe'):
                hints.append(dict(kind='os_cpe', value=cpe.text or '', xml_path=ref + '/cpe'))
    for port in host.findall('./ports/port'):
        service = port.find('service')
        state = port.find('state')
        if service is None or state is None or state.get('state') != 'open' or service.get('method') != 'probed':
            continue
        ref = f"ports/port[@protocol='{port.get('protocol')}'][@portid='{port.get('portid')}']/service"
        if service.get('ostype'):
            hints.append(dict(kind='service_ostype', value=service.get('ostype'), xml_path=ref,
                              attributes=dict(service.attrib)))
        for cpe in service.findall('cpe'):
            # Application CPEs cannot establish the host OS.
            value = (cpe.text or '').strip()
            if value.startswith(('cpe:/o:', 'cpe:2.3:o:')):
                hints.append(dict(kind='service_os_cpe', value=value, xml_path=ref + '/cpe'))
    return dict(addresses=[dict(a.attrib) for a in host.findall('address')],
                hostnames=[dict(h.attrib) for h in host.findall('./hostnames/hostname')],
                os_hints=hints)


def family(hint):
    value = hint['value'].strip().lower()
    if hint['kind'].endswith('cpe'):
        # Deliberately limited mapping of structured OS CPEs, not product substrings.
        match = re.match(r'^cpe:(?:/o:|2\.3:o:)([^:]+):([^:]+)(?::|$)', value)
        if not match:
            return None
        vendor, product = match.groups()
        if vendor == 'microsoft' and (product == 'windows' or product.startswith('windows_')):
            return 'windows'
        return {('linux', 'linux_kernel'): 'linux', ('freebsd', 'freebsd'): 'freebsd',
                ('openbsd', 'openbsd'): 'openbsd', ('netbsd', 'netbsd'): 'netbsd',
                ('apple', 'mac_os_x'): 'macos', ('apple', 'macos'): 'macos',
                ('google', 'android'): 'android', ('sun', 'solaris'): 'solaris',
                ('oracle', 'solaris'): 'solaris'}.get((vendor, product))
    return FAMILIES.get(value)


def confirmed_protocol(observation):
    if observation['state'] != 'open':
        return None
    service = observation['service']
    if observation.get('smb_dialects'):
        return 'smb'
    if service.get('method') != 'probed':
        return None
    name = service.get('name')
    if service.get('tunnel'):
        return 'https' if name in ('http', 'https') and service['tunnel'] == 'ssl' else None
    if name in ('https', 'microsoft-ds', 'netbios-ssn', 'smb'):
        return None  # Require the same positive TLS/dialect evidence as discovery.
    if name == 'modbus':
        for script in observation['scripts']:
            if script['attributes'].get('id') != 'modbus-discover':
                continue
            for table in script['children']:
                if table['tag'] == 'table' and table['attributes'].get('key', '').startswith('sid '):
                    if any(e['tag'] == 'elem' and e['attributes'].get('key') in
                           ('Slave ID data', 'Device identification') and e['text'] for e in table['children']):
                        return 'modbus'
        return None
    return name if name in ROLES else None


def describe(host_sources, observations, unresolved=()):
    hints = [{**hint, 'source_index': source['source_index']} for source in host_sources
             for hint in source['evidence']['os_hints']]
    for hint in hints:
        hint['candidate_family'] = family(hint)
    candidates = sorted({h['candidate_family'] for h in hints if h['candidate_family']})
    specific = set(candidates)
    if 'unix' in specific and specific & UNIX_FAMILIES:
        specific.remove('unix')
    # Android is not resolved to Linux solely from a kernel CPE.
    if specific == {'linux', 'android'}:
        specific.remove('linux')
    unknown = any(h['candidate_family'] is None for h in hints)
    value = next(iter(specific)) if len(specific) == 1 and not unknown else 'unknown'
    status = ('conflicting_evidence' if len(specific) > 1 else
              'unrecognized_evidence' if unknown else 'inferred' if specific else 'no_evidence')
    blocked = {(e['transport'], e['port']) for e in unresolved}
    roles = {}
    excluded = []
    for index, observation in enumerate(observations):
        if (observation['transport'], observation['port']) in blocked:
            excluded.append(index)
            continue
        protocol = confirmed_protocol(observation)
        if protocol in ROLES:
            roles.setdefault(ROLES[protocol], []).append(dict(
                observation_index=index, source_index=observation.get('source_index', 0),
                protocol=protocol, port=observation['port'], transport=observation['transport']))
    return dict(schema_version=1, policy='descriptive-device-profile-v1',
                selection_effect='none', os_family=value,
                os_assessment=dict(status=status, candidates=candidates, evidence=hints,
                                   confidence='not_calibrated',
                                   note='Observed hints are not verified host identity; Nmap accuracy is not a probability.'),
                roles=sorted(roles), role_evidence=roles,
                excluded_role_observation_indices=excluded,
                identity_observations=host_sources,
                physical_device_type='undetermined',
                limitations=['Only observed scan scope is represented; missing roles do not imply absence.',
                             'Banners, hostnames, OS hints and MAC vendors may be misleading or describe intermediaries.',
                             'A Modbus endpoint is not necessarily a PLC; SMB does not establish Windows.',
                             'This assessment never authorizes or selects a honeypot.'])
