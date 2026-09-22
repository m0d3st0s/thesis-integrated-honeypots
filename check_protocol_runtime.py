"""Read-only Service/listener checks after installing or upgrading mixed recipes.

These checks create no test connections. They do not replace external TLS/SMB
exchanges. /proc/net/tcp describes the shared pod network namespace.
"""
import argparse
import ipaddress
import json
import math
import subprocess
import time
from pathlib import Path
from protocol_support import requested_listeners


SOCKET_CODE = r'''
import json
from pathlib import Path
listeners = []
for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
    fields = line.split()
    if fields[3] == '0A':
        host, port = fields[1].split(':')
        listeners.append({'address_hex': host, 'port': int(port, 16)})
print(json.dumps(listeners))
'''


class RuntimeNotReady(ValueError):
    """A valid deployment may still be starting its processes/listeners."""


def get_json(argv, timeout=60):
    result = subprocess.run(argv, check=True, capture_output=True, text=True, timeout=timeout)
    return json.loads(result.stdout)


def verify(request, namespace, capture=get_json):
    selected = requested_listeners(request)
    name = request['name']
    service = capture(['kubectl', 'get', 'service', name, '-n', namespace, '-o', 'json'])
    spec = service['spec']
    expected = {s: (port, listener) for items in selected.values() for s, port, listener in items}
    actual = {p['name']: p for p in spec['ports']}
    if spec.get('type') != 'NodePort' or spec.get('externalTrafficPolicy') != 'Local' or set(actual) != set(expected):
        raise ValueError('Service type, traffic policy or selected port names differ from the request.')
    for protocol, (port, listener) in expected.items():
        p = actual[protocol]
        if (p['port'] != port or p['targetPort'] != listener or p.get('protocol', 'TCP') != 'TCP'
                or type(p.get('nodePort')) is not int):
            raise ValueError('Unexpected live Service mapping for ' + protocol)
    pods = capture(['kubectl', 'get', 'pods', '-n', namespace, '-l', 'app.kubernetes.io/instance=' + name, '-o', 'json'])
    active = [p for p in pods['items'] if not p['metadata'].get('deletionTimestamp')]
    if len(active) != 1 or not any(c['type'] == 'Ready' and c['status'] == 'True' for c in active[0]['status'].get('conditions', [])):
        raise RuntimeNotReady('Expected one Ready pod for listener verification.')
    pod = active[0]
    ip = pod['status']['podIP']
    ip_hex = ipaddress.IPv4Address(ip).packed[::-1].hex().upper()
    hp = 'dionaea' if 'dionaea' in selected else 'cowrie'
    python = 'python3' if hp == 'dionaea' else '/cowrie/cowrie-env/bin/python3'
    sockets = capture(['kubectl', 'exec', '-n', namespace, pod['metadata']['name'], '-c', hp, '--', python, '-c', SOCKET_CODE])
    bound = {s['port'] for s in sockets if s['address_hex'] in ('00000000', ip_hex)}
    missing = sorted({listener for _, listener in expected.values()} - bound)
    if missing:
        raise RuntimeNotReady('Selected IPv4 listeners are not bound on the pod: ' + str(missing))
    return {'status': 'passed', 'release': name, 'pod': pod['metadata']['name'],
            'pod_ip': ip, 'service_ports': list(actual.values()), 'listeners': sockets,
            'note': 'Passive pod-network listener checks; external protocol response and logging acceptance remain separate.'}


def wait_for_runtime(request, namespace, timeout=90, interval=2, *, capture=None,
                     clock=time.monotonic, pause=time.sleep, announce=None):
    """Retry only readiness/listener startup, under one overall deadline.

    Incorrect mappings, malformed responses and failed kubectl commands remain
    immediate errors. Each attempt re-reads the Service and current pod/IP.
    The default 90s deadline leaves room inside the callers' 120s process limit.
    """
    if not math.isfinite(timeout) or timeout <= 0 or not math.isfinite(interval) or interval <= 0:
        raise ValueError('Startup timeout and interval must be positive finite numbers.')
    started = clock()
    deadline = started + timeout
    attempts = 0
    last = 'No completed observation.'

    def expired():
        return ValueError('Application startup deadline exceeded after %g seconds (%d attempts). Last observation: %s'
                          % (timeout, attempts, last))

    def bounded_capture(command):
        remaining = deadline - clock()
        if remaining <= 0:
            raise expired()
        if capture is not None:
            return capture(command)
        return get_json(command, timeout=min(30, remaining))

    while True:
        if clock() >= deadline:
            raise expired()
        attempts += 1
        try:
            result = verify(request, namespace, bounded_capture)
        except RuntimeNotReady as exc:
            last = str(exc)
            remaining = deadline - clock()
            if remaining <= 0:
                raise expired() from exc
            if announce is not None:
                announce('Waiting for application startup (attempt %d): %s' % (attempts, last))
            pause(min(interval, remaining))
        else:
            if clock() >= deadline:
                raise expired()
            result['startup_wait'] = {'attempts': attempts, 'elapsed_seconds': round(clock() - started, 3),
                                      'timeout_seconds': timeout}
            return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--namespace', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout-seconds', type=float, default=90,
                        help='Maximum application startup wait (default: 90 seconds).')
    args = parser.parse_args()
    try:
        if args.output.exists():
            raise ValueError('Output already exists.')
        result = wait_for_runtime(json.loads(args.request.read_text()), args.namespace,
                                  timeout=args.timeout_seconds,
                                  announce=lambda message: print(message, flush=True))
        args.output.write_text(json.dumps(result, indent=2) + '\n')
        print('PASS: selected Service mappings and pod IPv4 listeners verified.')
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        parser.exit(1, 'Protocol runtime check failed: ' + str(exc) + '\n')


if __name__ == '__main__':
    main()
