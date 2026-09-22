"""Offline tests: real collectors and SQLite, fake kubectl; no cluster or scan."""
import argparse
import itertools
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
import honeypotctl as ctl
from report_config import load_config


class Reports(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        kubectl = self.bin / 'kubectl'
        kubectl.write_text('''#!/usr/bin/env python3
import json,sys
if sys.argv[2] == 'service':
 print(json.dumps({'spec':{'ports':[{'name':name,'port':port,'nodePort':nodeport} for name,port,nodeport in [('ssh',22,30022),('http',80,30080),('https',443,30443),('smb',445,30445)]]}}))
else: print(json.dumps({'items':[]}))
''')
        kubectl.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.bin) + ':' + os.environ['PATH'])
        (self.root / 'history').mkdir()
        (self.root / 'mixed.txt').write_text('')
        (self.root / 'conpot-labels.json').write_text('{"schema_version":1,"events":[]}')
        (self.root / 'kubeconfig').write_text('test fixture')
        self.mixed = dict(deployment='mixed-test', namespace='honeypots',
            database=str(self.root / 'dionaea.sqlite'), database_id='fresh-database',
            cowrie_log=str(self.root / 'cowrie.json'), labels=str(self.root / 'mixed.txt'),
            history_root=str(self.root / 'history'))
        self.conpot = dict(deployment='modbus-test', namespace='honeypots',
            log=str(self.root / 'conpot.json'), log_id='fresh-log', labels=str(self.root / 'conpot-labels.json'))

    def tearDown(self):
        self.temp.cleanup()

    def sources(self, selected):
        if 'cowrie' in selected:
            event = dict(eventid='cowrie.session.connect', timestamp='2026-09-22T09:00:00Z',
                         sensor='sensor', session='abc', src_ip='192.0.2.20', src_port=1234,
                         dst_ip='10.42.0.3', dst_port=2222, protocol='ssh')
            (self.root / 'cowrie.json').write_text(json.dumps(event) + '\n')
        if 'dionaea' in selected:
            with sqlite3.connect(self.root / 'dionaea.sqlite') as db:
                db.execute('CREATE TABLE connections (connection INTEGER, connection_type TEXT, connection_transport TEXT, connection_protocol TEXT, connection_timestamp REAL, local_host TEXT, local_port INTEGER, remote_host TEXT, remote_port INTEGER)')
                db.execute("INSERT INTO connections VALUES (1,'accept','tcp','httpd',1790067600,'10.42.0.3',80,'192.0.2.20',1235)")
        if 'conpot' in selected:
            event = dict(timestamp='2026-09-22T09:00:00', sensorid='modbus-test', id='xyz',
                         src_ip='192.0.2.20', src_port=1236, dst_ip='10.42.0.4', dst_port=5020,
                         data_type='modbus', request=None, response=None, event_type='NEW_CONNECTION')
            (self.root / 'conpot.json').write_text(json.dumps(event) + '\n')

    def collect(self, selected, suffix='out'):
        config = dict(schema_version=2, reports_root=str(self.root / 'reports'), kubeconfig=str(self.root / 'kubeconfig'))
        mixed = sorted(set(selected) & {'cowrie', 'dionaea'})
        if mixed:
            config['mixed'] = dict(self.mixed, services=mixed)
        if 'conpot' in selected:
            config['conpot'] = self.conpot
        cfg = self.root / 'reporting.json'
        cfg.write_text(json.dumps(config))
        completed = subprocess.run([sys.executable, str(PROJECT / 'report_config.py'), '--config', str(cfg),
                                    '--output', str(self.root / suffix), '2026-09-22T00:00:00Z', '2026-09-23T00:00:00Z'],
                                   env=self.env, text=True, capture_output=True)
        return completed, self.root / suffix / 'report'

    def test_all_seven_selections(self):
        # Each subcase uses fresh fixture directories: absent sources really do not exist.
        for size in (1, 2, 3):
            for selected in itertools.combinations(('cowrie', 'dionaea', 'conpot'), size):
                with self.subTest(selected=selected):
                    fixture = Reports()
                    fixture.setUp()
                    try:
                        fixture.sources(selected)
                        result, report = fixture.collect(selected)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        manifest = json.loads((report / 'collection-manifest.json').read_text())
                        self.assertEqual(manifest['status'], 'completed')
                        if set(selected) & {'cowrie', 'dionaea'}:
                            events = json.loads((report / 'ssh-http/window-feed.json').read_text())
                            self.assertEqual(events['total_incoming_connections'], len(set(selected) & {'cowrie', 'dionaea'}))
                            self.assertTrue(all(e['classification'] == 'unclassified' for e in events['connections']))
                        else:
                            self.assertEqual(manifest['sections']['ssh_http']['status'], 'not_selected')
                        if 'conpot' not in selected:
                            self.assertEqual(manifest['sections']['modbus']['status'], 'not_selected')
                    finally:
                        fixture.tearDown()

    def test_missing_selected_source_fails_not_zero(self):
        result, report = self.collect(['cowrie'])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads((report / 'collection-manifest.json').read_text())['sections']['ssh_http']['status'], 'failed')

    def test_missing_conpot_fails(self):
        result, report = self.collect(['conpot'])
        self.assertNotEqual(result.returncode, 0)

    def test_malformed_selected_log_fails(self):
        (self.root / 'cowrie.json').write_text('{broken}\n')
        result, _ = self.collect(['cowrie'])
        self.assertNotEqual(result.returncode, 0)

    def test_schema2_legacy_defaults(self):
        cfg = self.root / 'legacy.json'
        cfg.write_text(json.dumps(dict(schema_version=2, reports_root=str(self.root), mixed=self.mixed, conpot=self.conpot)))
        self.assertEqual(load_config(cfg)['mixed']['services'], ['cowrie', 'dionaea'])


class Workspace(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        kube = self.root / 'kube'
        kube.write_text('fixture')
        self.args = argparse.Namespace(workspace=self.root / 'workspace', network='192.0.2.0/24',
            scanner_ip='192.0.2.11', exclude=['192.0.2.10'], namespace='honeypots', mixed_release='test-mixed',
            conpot_release='test-modbus', interface='eth1', node_hostname='different-node',
            state_root=str(self.root / 'state'), log_root=str(self.root / 'logs'),
            honeychart_endpoint='http://127.0.0.1:8081/custom_build_endpoint', kubeconfig=kube)
        ctl.initialize(self.args)
        self.w, self.c, self.env = ctl.load_workspace(self.args.workspace)

    def tearDown(self):
        self.temp.cleanup()

    def prepare(self, selected=('cowrie', 'dionaea', 'conpot')):
        p = self.root / 'prepared'
        p.mkdir()
        (p / 'requests').mkdir()
        for file, target in [('runtime.json', 'runtime-config.json'), ('deployment.json', 'deployment-config.json')]:
            (p / target).write_bytes((self.w / file).read_bytes())
        for release, hps in [('test-mixed', sorted(set(selected) & {'cowrie', 'dionaea'})),
                             ('test-modbus', ['conpot'] if 'conpot' in selected else [])]:
            if hps:
                ctl.write(p / 'requests' / (release + '.request.json'), dict(name=release, honeypots={'names': hps, **{hp: dict(services=[{service: port}], containerports=[listener], protocols=['TCP']) for hp, service, port, listener in [('cowrie', 'ssh', 22, 2222), ('dionaea', 'http', 80, 80), ('conpot', 'modbus', 502, 5020)] if hp in hps}}))
        return p

    def test_no_original_labels_or_paths(self):
        self.assertEqual((self.w / 'labels/mixed.txt').read_text(), '')
        self.assertEqual(ctl.read(self.w / 'labels/conpot.json')['events'], [])
        scan = ctl.read(self.w / 'scan.json')
        self.assertEqual(scan['exclude_ips'], ['192.0.2.10', '192.0.2.11'])
        self.assertEqual(ctl.read(self.w / 'runtime.json')['node_hostname'], 'different-node')

    def test_rerun_init_refuses_without_changes(self):
        identity = self.c['identity']
        with self.assertRaises(FileExistsError):
            ctl.initialize(self.args)
        self.assertEqual(ctl.read(self.w / 'workspace.json')['identity'], identity)

    def test_ids_stable_for_upgrade_and_sources_selected(self):
        p = self.prepare(['cowrie'])
        first = ctl.reporting_settings(self.w, self.c, p)
        second = ctl.reporting_settings(self.w, self.c, p)
        self.assertEqual(first, second)
        self.assertNotIn('conpot', first)
        self.assertEqual(first['mixed']['services'], ['cowrie'])
        self.assertTrue(first['mixed']['database_id'].startswith(self.c['identity']))

    def test_changed_storage_rejected(self):
        p = self.prepare()
        runtime = ctl.read(p / 'runtime-config.json')
        runtime['state_root'] += '-different'
        ctl.write(p / 'runtime-config.json', runtime)
        with self.assertRaisesRegex(ValueError, 'layout changed'):
            ctl.reporting_settings(self.w, self.c, p)

    def test_invalid_network_has_no_side_effects(self):
        self.args.workspace = self.root / 'invalid'
        self.args.scanner_ip = '198.51.100.11'
        with self.assertRaises(ValueError):
            ctl.initialize(self.args)
        self.assertFalse(self.args.workspace.exists())

    def test_operation_lock(self):
        with ctl.locked(self.w):
            with self.assertRaisesRegex(ValueError, 'operation is active'):
                with ctl.locked(self.w):
                    pass

    def test_prerequisite_failure_prevents_scan(self):
        args = argparse.Namespace(mode='install', since=None)
        with patch.object(ctl, 'doctor', return_value={'status': 'failed', 'checks': []}), patch.object(ctl, 'call') as calls:
            with self.assertRaisesRegex(ValueError, 'Prerequisite'):
                ctl.run_workspace(args, self.w, self.c, self.env)
            calls.assert_not_called()
        manifests = list((self.w / 'runs').glob('*/workflow.json'))
        self.assertEqual(ctl.read(manifests[0])['status'], 'failed')
        self.assertFalse((self.w / 'reporting.json').exists())


if __name__ == '__main__':
    unittest.main()
