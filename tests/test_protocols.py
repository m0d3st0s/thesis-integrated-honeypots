"""Offline protocol regressions; no network access or Kubernetes required."""
import io
import itertools
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
import scan_network
from build_plan_v2 import build_plan
from build_requests import make_requests
from check_protocol_runtime import verify
from prepare_protocol_chart import prepare
from profiler_v3 import profile_scan
from protocol_support import LISTENERS, requested_listeners, reporting_protocols
from reconcile_profiles import reconcile
import test_workflow


def endpoint(port, name, method='probed', tunnel='', state='open'):
    return (f'<port protocol="tcp" portid="{port}"><state state="{state}"/>'
            f'<service name="{name}" method="{method}"'
            + (f' tunnel="{tunnel}"' if tunnel else '') + '/></port>')


SMB = '<hostscript><script id="smb-protocols"><table key="dialects"><elem>3.1.1</elem></table></script></hostscript>'
SMB_COLONS = ('<hostscript><script id="smb-protocols"><table key="dialects">'
              '<elem>2:0:2</elem><elem>2:1:0</elem><elem>3:0:0</elem>'
              '<elem>3:0:2</elem><elem>3:1:1</elem></table></script></hostscript>')


def xml(ports, hostscript='', start=1):
    return (f'<nmaprun start="{start}"><host><status state="up"/>'
            '<address addr="192.0.2.20" addrtype="ipv4"/><ports>' + ports
            + '</ports>' + hostscript + f'</host><runstats><finished exit="success" time="{start + 1}"/></runstats></nmaprun>')


def request(protocols):
    hps = {'names': []}
    for hp, definitions in LISTENERS.items():
        selected = [p for p in protocols if p in definitions]
        if selected:
            hps['names'].append(hp)
            hps[hp] = dict(services=[{p: {'ssh': 22}.get(p, definitions[p])} for p in selected],
                           containerports=[definitions[p] for p in selected],
                           protocols=['TCP'] * len(selected), volumes=['/fixture/logs/' + hp])
    return dict(name='protocol-mixed', service={'type': 'NodePort'}, honeypots=hps)


class Discovery(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.catalog = self.root / 'service-catalog.json'
        self.catalog.write_bytes((PROJECT / 'config/service-catalog.json').read_bytes())

    def tearDown(self):
        self.temp.cleanup()

    def profile(self, ports, hostscript='', probe=None):
        path = self.root / 'scan.xml'
        path.write_text(xml(ports, hostscript))
        return profile_scan(path, self.catalog, smb_probe_port=probe)['devices'][0]

    def test_https_needs_probed_http_and_tls_not_a_port_guess(self):
        for port in (443, 8443):
            with self.subTest(port=port):
                device = self.profile(endpoint(port, 'http', tunnel='ssl'))
                self.assertEqual(device['recommendations'][0]['service'], 'https')
                self.assertEqual(device['recommendations'][0]['observed_port'], port)
        for name, method, tunnel in [('https', 'table', ''), ('http', 'table', 'ssl'),
                                     ('https', 'probed', ''), ('unknown', 'probed', 'ssl'),
                                     ('ssh', 'probed', 'ssl')]:
            with self.subTest(name=name, method=method, tunnel=tunnel):
                self.assertFalse(self.profile(endpoint(443, name, method, tunnel))['recommendations'])
        self.assertEqual(self.profile(endpoint(443, 'http'))['recommendations'][0]['service'], 'http')

    def test_smb_requires_positive_host_script_tied_to_single_endpoint(self):
        for port in (445, 1445):
            device = self.profile(endpoint(port, 'microsoft-ds', 'table'), SMB, probe=port)
            self.assertEqual(device['recommendations'][0]['service'], 'smb')
            self.assertEqual(device['observations'][0]['smb_dialects'], ['3.1.1'])
        self.assertFalse(self.profile(endpoint(445, 'microsoft-ds'))['recommendations'])
        self.assertFalse(self.profile(endpoint(445, 'microsoft-ds'), SMB)['recommendations'])
        self.assertFalse(self.profile(endpoint(445, 'microsoft-ds'), '<hostscript><script id="smb-protocols" output="ERROR"/></hostscript>', probe=445)['recommendations'])
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            self.profile(endpoint(445, 'microsoft-ds') + endpoint(139, 'netbios-ssn'), SMB, probe=445)
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            self.profile(endpoint(445, 'microsoft-ds'), SMB, probe=1445)

    def test_colon_dialects_are_normalized_with_raw_evidence_retained(self):
        device = self.profile(endpoint(445, 'microsoft-ds', 'table'), SMB_COLONS, probe=445)
        self.assertEqual([r['service'] for r in device['recommendations']], ['smb'])
        observation = device['observations'][0]
        self.assertEqual(observation['smb_dialects'], ['2.0.2', '2.1', '3.0', '3.0.2', '3.1.1'])
        raw = observation['host_scripts'][0]['children'][0]['children']
        self.assertEqual([item['text'] for item in raw], ['2:0:2', '2:1:0', '3:0:0', '3:0:2', '3:1:1'])

    def test_colon_smb_evidence_builds_a_plan_after_netbios_ssn_identification(self):
        self.evidence(endpoint(22, 'ssh') + endpoint(80, 'http')
                      + endpoint(445, 'netbios-ssn') + endpoint(8443, 'http', tunnel='ssl'), SMB_COLONS)
        plan = build_plan(self.root, PROJECT / 'config/lab-deployment.json')
        self.assertEqual(plan['status'], 'planned', plan['review_items'])
        self.assertEqual(plan['review_items'], [])
        listeners = requested_listeners(make_requests(plan)[0]['payload'])
        self.assertEqual(listeners['cowrie'], [('ssh', 22, 2222)])
        self.assertEqual(listeners['dionaea'], [('http', 80, 80), ('https', 443, 443), ('smb', 445, 445)])

    def test_colon_format_does_not_bypass_evidence_checks(self):
        port = endpoint(445, 'microsoft-ds', 'table')
        for invalid in ('9:9:9', '3:1', 'ERROR', '3:1:1 garbage'):
            script = SMB.replace('3.1.1', invalid)
            self.assertFalse(self.profile(port, script, probe=445)['recommendations'])
        self.assertFalse(self.profile(port, SMB_COLONS)['recommendations'])
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            self.profile(port + endpoint(139, 'netbios-ssn'), SMB_COLONS, probe=445)

    def evidence(self, general, smb_script=SMB):
        (self.root / 'services.xml').write_text(xml(general))
        (self.root / 'smb.xml').write_text(xml(endpoint(445, 'microsoft-ds', 'table'), smb_script, start=3))
        (self.root / 'scan-manifest.json').write_text(json.dumps(dict(status='completed',
            discovered_targets=['192.0.2.20'], profiles=[{'kind': 'general', 'source_xml': 'services.xml'},
                                                      {'kind': 'smb', 'source_xml': 'smb.xml', 'port': 445}])))

    def test_reconciliation_and_requests_keep_distinct_dionaea_services(self):
        self.evidence(endpoint(80, 'http') + endpoint(443, 'http', tunnel='ssl') + endpoint(445, 'microsoft-ds'))
        plan = build_plan(self.root, PROJECT / 'config/lab-deployment.json')
        self.assertEqual(plan['status'], 'planned')
        generated = make_requests(plan)[0]['payload']
        self.assertEqual(requested_listeners(generated)['dionaea'], [('http', 80, 80), ('https', 443, 443), ('smb', 445, 445)])

    def test_conflicting_protocol_evidence_blocks_plan(self):
        self.evidence(endpoint(445, 'http'))
        result = reconcile(self.root)
        self.assertEqual(result['status'], 'review_required')
        self.assertIn('conflict', result['review_items'][0]['reason'])
        with self.assertRaises(ValueError):
            make_requests(build_plan(self.root, PROJECT / 'config/lab-deployment.json'))

    def test_scanner_runs_smb_only_on_open_configured_endpoint(self):
        config = self.root / 'config.json'
        config.write_text(json.dumps(dict(schema_version=1, network='192.0.2.0/24',
            scanner_ip='192.0.2.11', interface='eth1', exclude_ips=[], tcp_ports=[443, 445],
            modbus_probe_ports=[], smb_probe_ports=[445])))
        commands = []
        def run(command, **kwargs):
            commands.append(command)
            if '-oX' in command:
                path = Path(command[command.index('-oX') + 1])
                content = {'discovery.xml': xml(''),
                           'services.xml': xml(endpoint(443, 'https', 'table', state='closed') + endpoint(445, 'microsoft-ds')),
                           'smb-001.xml': xml(endpoint(445, 'microsoft-ds', 'table'), SMB, start=3)}[path.name]
                path.write_text(content)
            return subprocess.CompletedProcess(command, 0)
        args = ['scan_network.py', '--config', str(config), '--catalog', str(self.catalog), '--output', str(self.root / 'out')]
        with patch.object(sys, 'argv', args), patch.object(scan_network.shutil, 'which', return_value='/fixture/tool'), \
                patch.object(scan_network.subprocess, 'check_output', return_value='[{"addr_info":[{"local":"192.0.2.11"}]}]'), \
                patch.object(scan_network.subprocess, 'run', side_effect=run), redirect_stdout(io.StringIO()):
            scan_network.main()
        probes = [c for c in commands if '+smb-protocols' in c]
        self.assertEqual(len(probes), 1)
        self.assertEqual(probes[0][probes[0].index('-p') + 1], '445')
        self.assertEqual(probes[0][probes[0].index('--script-args') + 1], 'smbport=445')
        self.assertIn('192.0.2.20', probes[0])
        self.assertNotIn('192.0.2.0/24', probes[0])
        manifest = json.loads((self.root / 'out/scan-manifest.json').read_text())
        self.assertEqual(manifest['profiles'][-1]['port'], 445)


class Recipes(unittest.TestCase):
    def test_added_protocols_keep_workspace_source_identities(self):
        fixture = test_workflow.Workspace()
        fixture.setUp()
        try:
            prepared = fixture.prepare(['dionaea'])
            first = test_workflow.ctl.reporting_settings(fixture.w, fixture.c, prepared)
            req = request(['http', 'https', 'smb'])
            req['name'] = 'test-mixed'
            (prepared / 'requests/test-mixed.request.json').write_text(json.dumps(req))
            second = test_workflow.ctl.reporting_settings(fixture.w, fixture.c, prepared)
            self.assertEqual(first['mixed']['protocols'], ['http'])
            self.assertEqual(second['mixed']['protocols'], ['http', 'https', 'smb'])
            self.assertEqual(first['mixed']['database_id'], second['mixed']['database_id'])
            self.assertEqual(first['mixed']['database'], second['mixed']['database'])
            self.assertEqual(first['mixed']['labels'], second['mixed']['labels'])
        finally:
            fixture.tearDown()

    def template(self, req):
        # Fixture for the pinned generator's deployment anchors. This does not
        # replace live HoneyChart generation, Helm lint, or server validation.
        text = 'spec:\n  {{- if not .Values.autoscaling.enabled }}\n      serviceAccountName: fixture\n'
        for hp in req['honeypots']['names']:
            volume = 'dioanea-data' if hp == 'dionaea' else 'cowrie-data'
            text += f'image: {{{{ .Values.honeypots.{hp}.image.repository }}}}\n'
            text += f'            - mountPath: {{{{ .Values.volumes.{hp}mountPath }}}}\n              name: {volume}\n'
            text += f'            path: {{{{ .Values.volumes.{hp}hostPath }}}}\n'
        return text + '      volumes:\n'

    def test_all_fifteen_mixed_protocol_selections_prepare(self):
        for count in range(1, 5):
            for protocols in itertools.combinations(('ssh', 'http', 'https', 'smb'), count):
                with self.subTest(protocols=protocols), tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    req = request(protocols)
                    chart = root / req['name']
                    (chart / 'templates').mkdir(parents=True)
                    (chart / 'templates/deployment.yaml').write_text(self.template(req))
                    path = root / 'request.json'
                    path.write_text(json.dumps(req))
                    with redirect_stdout(io.StringIO()):
                        prepare(chart, path, root / 'state', 'fixture-node')
                    values = json.loads((root / (req['name'] + '-recipe-values.json')).read_text())
                    selected = requested_listeners(req)
                    self.assertEqual(set(values['honeypots']), set(selected))
                    for hp, items in selected.items():
                        ports = values['honeypots'][hp]['ports']
                        self.assertEqual(len(ports), 4 * len(items))
                        for service, port, listener in items:
                            self.assertEqual(ports['port' + service], port)
                            self.assertEqual(ports['containerPort' + service], listener)
                    self.assertFalse((root / 'state').exists())

    def test_invalid_listener_or_selection_refused(self):
        for field, value in [('containerports', [8443]), ('protocols', ['UDP']),
                             ('services', [{'https': 443}, {'https': 444}])]:
            req = request(['https'])
            req['honeypots']['dionaea'][field] = value
            with self.assertRaises(ValueError):
                requested_listeners(req)
        with self.assertRaises(ValueError):
            reporting_protocols(['ssh', 'https'], ['dionaea'])

    def runtime(self, req, listeners):
        ports = [dict(name=p, port=port, targetPort=listener, nodePort=30000 + port)
                 for items in requested_listeners(req).values() for p, port, listener in items]
        self.service = {'spec': dict(type='NodePort', externalTrafficPolicy='Local', ports=ports)}
        pod = dict(metadata={'name': 'fixture-pod'}, status=dict(podIP='10.42.0.6', conditions=[{'type': 'Ready', 'status': 'True'}]))
        return lambda cmd: self.service if 'service' in cmd else {'items': [pod]} if 'get' in cmd else listeners

    def test_runtime_requires_actual_listeners_and_service_mapping(self):
        req = request(['http', 'https', 'smb'])
        capture = self.runtime(req, [{'address_hex': '00000000', 'port': p} for p in (80, 443, 445)])
        self.assertEqual(verify(req, 'honeypots', capture)['status'], 'passed')
        self.service['spec']['ports'][1]['targetPort'] = 80
        with self.assertRaisesRegex(ValueError, 'mapping'):
            verify(req, 'honeypots', capture)
        for sockets in ([{'address_hex': '00000000', 'port': 80}],
                        [{'address_hex': '0100007F', 'port': p} for p in (80, 443, 445)]):
            with self.assertRaisesRegex(ValueError, 'not bound'):
                verify(req, 'honeypots', self.runtime(req, sockets))


class ProtocolReports(unittest.TestCase):
    def setUp(self):
        self.fixture = test_workflow.Reports()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.fixture.sources(['dionaea', 'cowrie'])
        self.root = self.fixture.root
        with sqlite3.connect(self.root / 'dionaea.sqlite') as db:
            # Port alone must never decide HTTP versus HTTPS. Keep ID 1 for the
            # existing HTTP row and test an unknown transport and outbound row.
            for row in [(2, 'accept', 'tls', 'httpd', 443), (3, 'accept', 'tcp', 'smbd', 445),
                        (4, 'accept', 'udp', 'httpd', 443), (5, 'connect', 'tls', 'httpd', 443)]:
                db.execute('INSERT INTO connections VALUES (?,?,?,?,1790067600,\'10.42.0.3\',?,\'192.0.2.20\',1235)', row)

    def test_export_protocol_identity_not_port_and_stable_ids(self):
        result = subprocess.run([sys.executable, str(PROJECT / 'export_dionaea.py'), str(self.root / 'dionaea.sqlite'),
                                 '--database-id', 'fresh-database', '--deployment', 'mixed-test'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        events = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual([e['service'] for e in events], ['http', 'https', 'smb', None, 'https'])
        self.assertFalse(events[-1]['count_as_inbound_connection'])
        self.assertEqual(events[0]['event_id'], 'dionaea:fresh-database:connection:1')

    def test_all_dionaea_protocol_subsets_and_full_mixed_reporting(self):
        selections = [p for size in range(1, 4) for p in itertools.combinations(('http', 'https', 'smb'), size)]
        selections.append(('ssh', 'http', 'https', 'smb'))
        for index, protocols in enumerate(selections):
            with self.subTest(protocols=protocols):
                sources = ['cowrie', 'dionaea'] if 'ssh' in protocols else ['dionaea']
                self.fixture.mixed['protocols'] = list(protocols)
                result, report = self.fixture.collect(sources, suffix='out-' + str(index))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                feed = json.loads((report / 'ssh-http/window-feed.json').read_text())
                self.assertEqual(feed['total_incoming_connections'], len(protocols))
                self.assertEqual({e['service'] for e in feed['connections']}, set(protocols))
                self.assertEqual(feed['excluded_protocol_connections'], 4 + ('ssh' in protocols) - len(protocols))
                all_events = json.loads((report / 'ssh-http/all-connections.json').read_text())
                self.assertTrue(any(e['service'] is None for e in all_events['connections']))

    def test_old_configuration_keeps_all_selected_source_records(self):
        result, report = self.fixture.collect(['dionaea'])
        self.assertEqual(result.returncode, 0, result.stderr)
        feed = json.loads((report / 'ssh-http/window-feed.json').read_text())
        self.assertIsNone(feed['selected_protocols'])
        self.assertEqual(feed['total_incoming_connections'], 4)
        self.assertEqual(feed['excluded_protocol_connections'], 0)


if __name__ == '__main__':
    unittest.main()
