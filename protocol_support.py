"""Protocol names and fixed listener contract for the pinned mixed recipes."""

LISTENERS = {
    'cowrie': {'ssh': 2222},
    'dionaea': {'http': 80, 'https': 443, 'smb': 445},
}
PROTOCOL_OWNER = {service: hp for hp, ports in LISTENERS.items() for service in ports}


def requested_listeners(request):
    """Validate each selected service and preserve its request order."""
    hps = request['honeypots']
    names = hps['names']
    if not isinstance(names, list) or not names or len(set(names)) != len(names) or set(names) - LISTENERS.keys():
        raise ValueError('Expected Cowrie, Dionaea, or both.')
    result = {}
    all_ports = set()
    for hp in names:
        item = hps[hp]
        services = item['services']
        if not isinstance(services, list) or not services:
            raise ValueError('Empty service selection for ' + hp)
        if len(item['containerports']) != len(services) or item['protocols'] != ['TCP'] * len(services):
            raise ValueError('Invalid listener/protocol list for ' + hp)
        selected = []
        seen = set()
        for index, mapping in enumerate(services):
            if not isinstance(mapping, dict) or len(mapping) != 1:
                raise ValueError('Expected one protocol per service mapping.')
            service, port = next(iter(mapping.items()))
            if service not in LISTENERS[hp] or service in seen:
                raise ValueError('Unsupported or repeated service for ' + hp + ': ' + service)
            if type(port) is not int or not 1 <= port <= 65535 or port in all_ports:
                raise ValueError('Invalid or conflicting Service port.')
            listener = item['containerports'][index]
            if type(listener) is not int or listener != LISTENERS[hp][service]:
                raise ValueError('Unsupported container listener for ' + service)
            seen.add(service)
            all_ports.add(port)
            selected.append((service, port, listener))
        result[hp] = selected
    return result


def reporting_protocols(protocols, sources=None):
    if (not isinstance(protocols, list) or not protocols or
            any(not isinstance(p, str) or p not in PROTOCOL_OWNER for p in protocols) or
            len(set(protocols)) != len(protocols)):
        raise ValueError('protocols must select distinct ssh/http/https/smb names.')
    if sources is not None and {PROTOCOL_OWNER[p] for p in protocols} != set(sources):
        raise ValueError('Selected protocols and honeypot sources disagree.')
    return sorted(protocols)


def dionaea_service(protocol, transport):
    """Use recorded transport, never destination-port guesses, for TLS."""
    if protocol == 'httpd':
        return {'tcp': 'http', 'tls': 'https'}.get(transport)
    if protocol == 'smbd' and transport == 'tcp':
        return 'smb'
    return None
