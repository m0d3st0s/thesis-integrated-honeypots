"""Validated NodePort / MetalLB IPv4 exposure and collection-time endpoints."""
import ipaddress
import json
import re


def ipv4(value):
    if not isinstance(value, str):
        raise ValueError('LoadBalancer IP must be an IPv4 string.')
    address = ipaddress.IPv4Address(value)
    if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local or int(address) == 0xffffffff:
        raise ValueError('LoadBalancer IP must be a usable unicast address.')
    return str(address)


def pool_name(value):
    if not isinstance(value, str) or len(value) > 63 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', value):
        raise ValueError('A valid MetalLB address pool name is required.')
    return value


def validate_config(config):
    kind = config.get('service_type')
    lb = config.get('load_balancer')
    if kind == 'NodePort':
        if lb is not None:
            raise ValueError('NodePort must not contain load_balancer settings.')
        return {}
    if kind != 'LoadBalancer':
        raise ValueError('service_type must be NodePort or LoadBalancer.')
    if not isinstance(lb, dict) or set(lb) != {'address_pool', 'ips'}:
        raise ValueError('LoadBalancer requires load_balancer.address_pool and ips by release.')
    pool_name(lb['address_pool'])
    ips = lb['ips']
    releases = {item['release'] for item in config['mappings']}
    if not isinstance(ips, dict) or set(ips) != releases:
        raise ValueError('Assign one reserved LoadBalancer IP to every configured release.')
    values = [ipv4(value) for value in ips.values()]
    if len(set(values)) != len(values):
        raise ValueError('LoadBalancer releases must use distinct reserved IPs.')
    return {name: {'address_pool': lb['address_pool'], 'ip': ips[name]} for name in sorted(ips)}


def request_exposure(request):
    service = request['service']
    kind = service.get('type')
    if kind == 'NodePort':
        if service.get('loadBalancer') is not None or service.get('lbIp') is not None:
            raise ValueError('Unexpected LoadBalancer settings in a NodePort request.')
        return kind, {}
    if kind != 'LoadBalancer':
        raise ValueError('Unsupported Service type.')
    lb = service.get('loadBalancer')
    if not isinstance(lb, dict) or set(lb) != {'address_pool', 'ip'}:
        raise ValueError('Missing MetalLB pool and reserved IP in request.')
    address = ipv4(lb['ip'])
    if service.get('lbIp') != address:
        raise ValueError('HoneyChart IP and requested LoadBalancer IP disagree.')
    return kind, {'metallb.io/address-pool': pool_name(lb['address_pool']),
                  'metallb.io/loadBalancerIPs': address}


def service_template(request):
    """Own the final single Service, including stable release name for both modes.

    HoneyChart's LB branch adds numeric name suffixes and deprecated fields;
    replace its service template as part of the versioned preparation recipe.
    """
    kind, annotations = request_exposure(request)
    release = request['name']
    if not isinstance(release, str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{1,18}[a-z0-9]', release):
        raise ValueError('Invalid release name.')
    ports = []
    for hp in request['honeypots']['names']:
        item = request['honeypots'][hp]
        for index, mapping in enumerate(item['services']):
            name, port = next(iter(mapping.items()))
            ports.append({'name': name, 'port': port, 'targetPort': item['containerports'][index],
                          'protocol': item['protocols'][index]})
    # JSON is YAML-compatible, and static data cannot become a Helm expression.
    # The selectors follow the pinned chart's standard helper convention.
    obj = {'apiVersion': 'v1', 'kind': 'Service',
           'metadata': {'name': release, 'labels': {'app.kubernetes.io/instance': release,
                        'app.kubernetes.io/name': release}, 'annotations': annotations},
           'spec': {'type': kind, 'externalTrafficPolicy': 'Local', 'ports': ports,
                    'selector': {'app.kubernetes.io/instance': release, 'app.kubernetes.io/name': release}}}
    if kind == 'LoadBalancer':
        obj['spec']['allocateLoadBalancerNodePorts'] = True
    return json.dumps(obj, indent=2) + '\n'


def endpoint_summary(service):
    spec = service.get('spec', {})
    ingress = service.get('status', {}).get('loadBalancer', {}).get('ingress', [])
    addresses = [item.get('ip') or item.get('hostname') for item in ingress if item.get('ip') or item.get('hostname')]
    return {'service_type': spec.get('type', 'ClusterIP'), 'load_balancer_addresses': addresses,
            'ports': [{'name': p.get('name'), 'service_port': p.get('port'), 'node_port': p.get('nodePort'),
                       'load_balancer_endpoints': [f'{host}:{p["port"]}' for host in addresses]}
                      for p in spec.get('ports', [])],
            'meaning': 'Service configuration at collection time; not proof of an event destination or external reachability.'}


def pool_contains(address, ranges):
    ip = ipaddress.IPv4Address(address)
    for value in ranges:
        if '-' in value:
            start, end = (ipaddress.IPv4Address(part.strip()) for part in value.split('-', 1))
            if start <= ip <= end:
                return True
        else:
            try:
                if ip in ipaddress.IPv4Network(value, strict=False):
                    return True
            except ipaddress.AddressValueError:
                continue  # An IPv6-only range cannot contain this IPv4 address.
    return False


def check_metallb(config, scan, capture):
    """Read cluster configuration; cannot establish administrative reservation."""
    exposure = validate_config(config)
    if not exposure:
        return 'NodePort; no LoadBalancer controller required.'
    requested = {settings['ip']: release for release, settings in exposure.items()}
    network = ipaddress.IPv4Network(scan['network'])
    for address in requested:
        ip = ipaddress.IPv4Address(address)
        if ip in network and address not in scan['exclude_ips']:
            raise ValueError('Exclude reserved LoadBalancer IPs from discovery: ' + address)
        if address == scan['scanner_ip'] or ip in (network.network_address, network.broadcast_address):
            raise ValueError('LoadBalancer IP conflicts with scanner or network boundary.')
    nodes = capture(['kubectl', 'get', 'nodes', '-o', 'json'])['items']
    node_ips = {a['address'] for n in nodes for a in n.get('status', {}).get('addresses', []) if a['type'] in ('InternalIP', 'ExternalIP')}
    if node_ips & requested.keys():
        raise ValueError('LoadBalancer IP is already assigned to a Kubernetes node.')
    pools = capture(['kubectl', 'get', 'ipaddresspools.metallb.io', '-A', '-o', 'json'])['items']
    pool = config['load_balancer']['address_pool']
    matches = [p for p in pools if p['metadata']['name'] == pool]
    if len(matches) != 1:
        raise ValueError('Expected exactly one existing MetalLB IPAddressPool named ' + pool)
    resource = matches[0]
    if not all(pool_contains(ip, resource['spec']['addresses']) for ip in requested):
        raise ValueError('Reserved IPs do not belong to the selected MetalLB pool.')
    ns = resource['metadata']['namespace']
    adverts = capture(['kubectl', 'get', 'l2advertisements.metallb.io', '-n', ns, '-o', 'json'])['items']
    # Deliberately require explicit pool names: selector-based configurations need
    # separate validation; do not report success based on an unevaluated selector.
    if not any(pool in a['spec'].get('ipAddressPools', []) for a in adverts):
        raise ValueError('An L2Advertisement must explicitly include this pool.')
    services = capture(['kubectl', 'get', 'services', '-A', '-o', 'json'])['items']
    for svc in services:
        meta = svc['metadata']
        claims = set(endpoint_summary(svc)['load_balancer_addresses'])
        claims.update(svc.get('spec', {}).get('externalIPs', []))
        claims.update(svc.get('spec', {}).get('clusterIPs', []))
        annotations = meta.get('annotations', {})
        for key in ('metallb.io/loadBalancerIPs', 'metallb.universe.tf/loadBalancerIPs'):
            claims.update(x.strip() for x in annotations.get(key, '').split(',') if x.strip())
        if svc.get('spec', {}).get('loadBalancerIP'):
            claims.add(svc['spec']['loadBalancerIP'])
        for ip in claims & requested.keys():
            if (meta['namespace'], meta['name']) != (config['namespace'], requested[ip]):
                raise ValueError('Reserved IP is already claimed by another Service: ' + ip)
    return ('MetalLB pool, explicit L2 advertisement and visible address conflicts checked. '
            'DHCP/static reservation, controller health and external reachability require operator/live validation.')
