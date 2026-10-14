"""Offline MetalLB configuration, request, runtime and real report regressions."""
import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import honeypotctl as ctl
from build_plan_v2 import build_plan
from build_requests import make_requests
from check_protocol_runtime import verify, wait_for_runtime
from service_exposure import (validate_config, request_exposure, service_template,
                              endpoint_summary, pool_contains, check_metallb)
import test_protocols
import test_runtime_startup
import test_workflow

PROJECT = Path(__file__).resolve().parents[1]


def config():
    value = json.loads((PROJECT / 'config/lab-deployment.json').read_text())
    value['service_type'] = 'LoadBalancer'
    value['load_balancer'] = {'address_pool': 'lab-pool',
        'ips': {'auto-mixed-01': '192.0.2.240', 'ics-modbus-01': '192.0.2.241'}}
    return value


def request():
    value = copy.deepcopy(test_runtime_startup.REQUEST)
    value['service'] = {'type': 'LoadBalancer', 'lbIp': '192.0.2.240',
        'loadBalancer': {'address_pool': 'lab-pool', 'ip': '192.0.2.240'}}
    return value


class Configuration(unittest.TestCase):
    def test_duplicate_missing_invalid_or_nodeport_lb_settings_fail(self):
        for mutation in ('duplicate', 'missing', 'invalid', 'pool', 'nodeport'):
            c = config()
            if mutation == 'duplicate': c['load_balancer']['ips']['ics-modbus-01'] = '192.0.2.240'
            if mutation == 'missing': del c['load_balancer']['ips']['ics-modbus-01']
            if mutation == 'invalid': c['load_balancer']['ips']['ics-modbus-01'] = '127.0.0.1'
            if mutation == 'pool': c['load_balancer']['address_pool'] = '{{ bad }}'
            if mutation == 'nodeport': c['service_type'] = 'NodePort'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): validate_config(c)

    def test_plan_propagates_reserved_ip_without_changing_protocol_decisions(self):
        profile = {'devices': [{'ip': '192.0.2.20', 'recommendations': [
            dict(honeypot='cowrie', service='ssh', transport='tcp', observed_port=22,
                 observation_index=0, supporting_source_index=0)]}], 'review_items': [], 'sources': []}
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / 'config.json'
            c = config(); p.write_text(json.dumps(c))
            with patch('build_plan_v2.reconcile', return_value=profile): lb = build_plan(Path(temp), p)
            c.pop('load_balancer'); c['service_type'] = 'NodePort'; p.write_text(json.dumps(c))
            with patch('build_plan_v2.reconcile', return_value=profile): node = build_plan(Path(temp), p)
            self.assertEqual(lb['releases'][0]['services'], node['releases'][0]['services'])
            payload = make_requests(lb)[0]['payload']
            self.assertEqual(request_exposure(payload)[1]['metallb.io/loadBalancerIPs'], '192.0.2.240')

    def test_reserved_ip_among_discovered_hosts_blocks_plan(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / 'config.json'; p.write_text(json.dumps(config()))
            with patch('build_plan_v2.reconcile', return_value={'devices': [{'ip': '192.0.2.240'}]}):
                with self.assertRaisesRegex(ValueError, 'scanned targets'): build_plan(Path(temp), p)

    def test_init_excludes_vips_and_invalid_input_creates_no_workspace(self):
        fixture = test_workflow.Workspace(); fixture.setUp()
        try:
            a = copy.deepcopy(fixture.args)
            a.workspace = fixture.root / 'lb-workspace'
            a.service_type = 'LoadBalancer'; a.metallb_pool = 'lab-pool'
            a.mixed_lb_ip = '192.0.2.240'; a.conpot_lb_ip = '192.0.2.241'
            ctl.initialize(a)
            scan = ctl.read(a.workspace / 'scan.json')
            self.assertTrue({'192.0.2.240', '192.0.2.241'} <= set(scan['exclude_ips']))
            a.workspace = fixture.root / 'invalid'; a.mixed_lb_ip = a.scanner_ip
            with self.assertRaises(ValueError): ctl.initialize(a)
            self.assertFalse(a.workspace.exists())
        finally: fixture.tearDown()

    def test_request_ip_mismatch_and_template_injection_fail(self):
        r = request(); r['service']['lbIp'] = '192.0.2.242'
        with self.assertRaises(ValueError): request_exposure(r)
        r = request(); r['name'] = '{{ evil }}'
        with self.assertRaises(ValueError): service_template(r)

    def test_final_service_has_stable_name_no_deprecated_ip_and_all_ports(self):
        r = request(); obj = json.loads(service_template(r))
        self.assertEqual(obj['metadata']['name'], r['name'])
        self.assertNotIn('loadBalancerIP', obj['spec'])
        self.assertEqual(obj['spec']['externalTrafficPolicy'], 'Local')
        self.assertTrue(obj['spec']['allocateLoadBalancerNodePorts'])
        self.assertEqual({p['name'] for p in obj['spec']['ports']}, {'http', 'https', 'smb', 'ssh'})
        self.assertEqual(obj['metadata']['annotations']['metallb.io/address-pool'], 'lab-pool')


class Prerequisites(unittest.TestCase):
    def setUp(self):
        self.scan = {'network': '192.0.2.0/24', 'scanner_ip': '192.0.2.11',
                     'exclude_ips': ['192.0.2.11', '192.0.2.240', '192.0.2.241']}
        self.nodes = []
        self.pools = [{'metadata': {'name': 'lab-pool', 'namespace': 'metallb-system'},
                       'spec': {'addresses': ['192.0.2.240-192.0.2.241']}}]
        self.adverts = [{'spec': {'ipAddressPools': ['lab-pool']}}]
        self.services = []

    def capture(self, command):
        return {'items': {'nodes': self.nodes, 'ipaddresspools.metallb.io': self.pools,
            'l2advertisements.metallb.io': self.adverts, 'services': self.services}[command[2]]}

    def test_valid_pool_cidr_and_range(self):
        self.assertTrue(pool_contains('192.0.2.240', ['192.0.2.240/31']))
        self.assertFalse(pool_contains('192.0.2.242', ['192.0.2.240-192.0.2.241']))
        self.assertIn('reservation', check_metallb(config(), self.scan, self.capture))

    def test_missing_pool_advertisement_and_exclusion_fail(self):
        for which in ('pool', 'advertisement', 'exclusion', 'range'):
            self.setUp()
            if which == 'pool': self.pools = []
            if which == 'advertisement': self.adverts = []
            if which == 'exclusion': self.scan['exclude_ips'] = []
            if which == 'range': self.pools[0]['spec']['addresses'] = ['192.0.2.250/32']
            with self.subTest(which=which), self.assertRaises(ValueError):
                check_metallb(config(), self.scan, self.capture)

    def test_node_ip_and_other_service_claim_fail(self):
        self.nodes = [{'status': {'addresses': [{'type': 'InternalIP', 'address': '192.0.2.240'}]}}]
        with self.assertRaisesRegex(ValueError, 'node'): check_metallb(config(), self.scan, self.capture)
        self.nodes = []
        self.services = [{'metadata': {'name': 'other', 'namespace': 'honeypots',
                         'annotations': {'metallb.io/loadBalancerIPs': '192.0.2.240'}}, 'spec': {}}]
        with self.assertRaisesRegex(ValueError, 'another Service'): check_metallb(config(), self.scan, self.capture)
        self.services[0]['metadata']['name'] = 'auto-mixed-01'
        check_metallb(config(), self.scan, self.capture)  # same release upgrade


class Runtime(unittest.TestCase):
    def cluster(self, address='192.0.2.240', after=1, annotations=True):
        base = test_runtime_startup.Cluster()
        def capture(command):
            value = base(command)
            if 'service' in command:
                value['spec'].update(type='LoadBalancer', allocateLoadBalancerNodePorts=True)
                value['metadata'] = {'annotations': request_exposure(request())[1] if annotations else {}}
                value['status'] = {'loadBalancer': {'ingress': [{'ip': address}] if base.attempts >= after and address else []}}
            return value
        return capture

    def test_pending_allocation_is_retried_then_successful(self):
        clock = test_runtime_startup.Clock()
        result = wait_for_runtime(request(), 'honeypots', capture=self.cluster(after=3), clock=clock, pause=clock.sleep)
        self.assertEqual(result['startup_wait']['attempts'], 3)
        self.assertEqual(result['exposure']['load_balancer_addresses'], ['192.0.2.240'])

    def test_permanently_pending_does_not_pass(self):
        clock = test_runtime_startup.Clock()
        with self.assertRaisesRegex(ValueError, 'deadline.*pending'):
            wait_for_runtime(request(), 'honeypots', timeout=3, capture=self.cluster(address=None), clock=clock, pause=clock.sleep)

    def test_wrong_ip_or_annotations_fail_immediately(self):
        for capture in (self.cluster(address='192.0.2.242'), self.cluster(annotations=False)):
            with self.assertRaises(ValueError): verify(request(), 'honeypots', capture)

    def test_conpot_gets_service_and_listener_validation(self):
        r = request(); r['honeypots'] = {'names': ['conpot'], 'conpot': {
            'services': [{'modbus': 502}], 'containerports': [5020], 'protocols': ['TCP']}}
        def capture(command):
            if 'service' in command:
                s = json.loads(service_template(r)); s['spec']['ports'][0]['nodePort'] = 30502
                s['status'] = {'loadBalancer': {'ingress': [{'ip': '192.0.2.240'}]}}
                return s
            if 'get' in command:
                return {'items': [{'metadata': {'name': 'modbus-pod'}, 'status': {'podIP': '10.42.0.2',
                    'conditions': [{'type': 'Ready', 'status': 'True'}]}}]}
            self.assertEqual(command[command.index('-c') + 1], 'conpot')
            return [{'address_hex': '00000000', 'port': 5020}]
        self.assertEqual(verify(r, 'honeypots', capture)['status'], 'passed')


class Reporting(unittest.TestCase):
    def test_collector_displays_addresses_for_both_sections_without_changing_counts(self):
        fixture = test_workflow.Reports(); fixture.setUp()
        try:
            script = fixture.bin / 'kubectl'
            script.write_text('''#!/usr/bin/env python3
import json,sys
if sys.argv[2] == 'service':
 p = {'name':'http','port':80,'nodePort':30080} if sys.argv[3] == 'mixed-test' else {'name':'modbus','port':502,'nodePort':30502}
 print(json.dumps({'spec':{'type':'LoadBalancer','ports':[p]},'status':{'loadBalancer':{'ingress':[{'ip':'192.0.2.240'}]}}}))
else: print(json.dumps({'items':[]}))
''')
            fixture.sources(['dionaea', 'conpot'])
            result, folder = fixture.collect(['dionaea', 'conpot'])
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            text = (folder / 'report.txt').read_text()
            self.assertIn('192.0.2.240:80', text); self.assertIn('192.0.2.240:502', text)
            self.assertIn('Total connections: 1', text)
            self.assertIn('Logged connection starts: 1', text)
            data = json.loads((folder / 'ssh-http/service-exposure.json').read_text())
            self.assertIn('not proof', data['meaning'])
        finally: fixture.tearDown()


if __name__ == '__main__': unittest.main()
