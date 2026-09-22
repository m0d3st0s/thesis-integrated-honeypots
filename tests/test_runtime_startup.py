"""Bounded startup polling without sleeping or contacting a cluster."""
import subprocess
import unittest
from unittest.mock import patch

from check_protocol_runtime import wait_for_runtime

REQUEST = {'name': 'protocol-mixed', 'honeypots': {'names': ['dionaea', 'cowrie'],
    'dionaea': {'services': [{'http': 80}, {'https': 443}, {'smb': 445}],
                'containerports': [80, 443, 445], 'protocols': ['TCP'] * 3},
    'cowrie': {'services': [{'ssh': 22}], 'containerports': [2222], 'protocols': ['TCP']}}}


class Clock:
    def __init__(self):
        self.now = 0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class Cluster:
    def __init__(self, ready_after=1, pod_after=1):
        self.attempts = 0
        self.ready_after = ready_after
        self.pod_after = pod_after
        self.executed_pods = []
        self.bad_mapping = False

    def __call__(self, command):
        if 'service' in command:
            self.attempts += 1
            ports = [dict(name=name, port=port, targetPort=listener, nodePort=30000 + port)
                     for name, port, listener in [('http', 80, 80), ('https', 443, 443),
                                                  ('smb', 445, 445), ('ssh', 22, 2222)]]
            if self.bad_mapping:
                ports[0]['targetPort'] = 9999
            return {'spec': dict(type='NodePort', externalTrafficPolicy='Local', ports=ports)}
        if 'get' in command:
            if self.attempts < self.pod_after:
                return {'items': []}
            return {'items': [dict(metadata=dict(name='pod-' + str(self.attempts)),
                                  status=dict(podIP='10.42.0.' + str(self.attempts),
                                              conditions=[{'type': 'Ready', 'status': 'True'}]))]}
        self.executed_pods.append(command[4])
        if self.attempts < self.ready_after:
            return []
        return [{'address_hex': '%02X002A0A' % self.attempts, 'port': p} for p in (80, 443, 445, 2222)]


class Startup(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.messages = []

    def run_check(self, cluster, **kwargs):
        return wait_for_runtime(REQUEST, 'honeypots', capture=cluster,
                                clock=self.clock, pause=self.clock.sleep,
                                announce=self.messages.append, **kwargs)

    def test_delayed_listeners_succeed_and_recheck_current_pod(self):
        cluster = Cluster(ready_after=3)
        result = self.run_check(cluster)
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(result['pod'], 'pod-3')
        self.assertEqual(cluster.executed_pods, ['pod-1', 'pod-2', 'pod-3'])
        self.assertEqual(result['startup_wait']['attempts'], 3)
        self.assertEqual(self.clock.sleeps, [2, 2])
        self.assertEqual(len(self.messages), 2)

    def test_missing_ready_pod_is_retried(self):
        cluster = Cluster(pod_after=2)
        result = self.run_check(cluster)
        self.assertEqual(result['startup_wait']['attempts'], 2)
        self.assertEqual(cluster.executed_pods, ['pod-2'])

    def test_already_listening_does_not_sleep(self):
        result = self.run_check(Cluster())
        self.assertEqual(result['startup_wait']['attempts'], 1)
        self.assertEqual(self.clock.sleeps, [])

    def test_never_listening_stops_at_deadline(self):
        cluster = Cluster(ready_after=100)
        with self.assertRaisesRegex(ValueError, 'deadline exceeded.*not bound'):
            self.run_check(cluster, timeout=5, interval=2)
        self.assertEqual(self.clock.now, 5)
        self.assertEqual(cluster.attempts, 3)
        self.assertEqual(self.clock.sleeps, [2, 2, 1])

    def test_invalid_mapping_is_not_retried(self):
        cluster = Cluster()
        cluster.bad_mapping = True
        with self.assertRaisesRegex(ValueError, 'mapping'):
            self.run_check(cluster)
        self.assertEqual(cluster.attempts, 1)
        self.assertEqual(self.clock.sleeps, [])

    def test_failed_kubectl_command_is_not_hidden_as_startup(self):
        def denied(command):
            raise subprocess.CalledProcessError(1, command, stderr='Forbidden')
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_check(denied)
        self.assertEqual(self.clock.sleeps, [])

    def test_each_command_timeout_respects_remaining_budget(self):
        cluster = Cluster()
        budgets = []
        def get(command, timeout):
            budgets.append(timeout)
            self.clock.now += 1
            return cluster(command)
        with patch('check_protocol_runtime.get_json', get):
            result = wait_for_runtime(REQUEST, 'honeypots', timeout=5,
                                      clock=self.clock, pause=self.clock.sleep)
        self.assertEqual(budgets, [5, 4, 3])
        self.assertEqual(result['startup_wait']['elapsed_seconds'], 3)

    def test_invalid_deadlines_are_rejected_before_queries(self):
        for value in (0, -1, float('inf'), float('nan')):
            cluster = Cluster()
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'positive finite'):
                self.run_check(cluster, timeout=value)
            self.assertEqual(cluster.attempts, 0)
