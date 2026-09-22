"""Exercise real orchestration using simulated stage executables, no deployment."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import honeypotctl as ctl


STAGE = r'''
import json, shutil, sys
from pathlib import Path
args = sys.argv[1:]
def arg(name): return args[args.index(name)+1]
root = Path(__file__).parent
mode = (root / 'scenario').read_text()
out = Path(arg('--output'))
out.mkdir(parents=True)
script = Path(__file__).name
if script == 'run_system.py':
    (out / 'system-run.json').write_text(json.dumps({'status': 'no_targets' if mode == 'empty' else 'prepared'}))
    if mode != 'empty':
        p = out / 'prepared'
        (p / 'requests').mkdir(parents=True)
        shutil.copyfile(arg('--runtime-config'), p / 'runtime-config.json')
        shutil.copyfile(arg('--deployment-config'), p / 'deployment-config.json')
        (p / 'requests/mixed.request.json').write_text(json.dumps({'name':'mixed-test','honeypots':{'names':['cowrie'],'cowrie':{'services':[{'ssh':22}],'containerports':[2222],'protocols':['TCP']}}}))
elif script in ('install_prepared.py', 'deploy_prepared.py'):
    if mode == 'deployment_failure': sys.exit(3)
    (out / 'result.json').write_text('{"status":"completed"}')
elif mode == 'report_failure':
    sys.exit(4)
else:
    (out / 'result.json').write_text('{"status":"completed"}')
'''


class Orchestration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / 'project'
        self.project.mkdir()
        for script in ('run_system.py', 'install_prepared.py', 'deploy_prepared.py', 'report_config.py'):
            (self.project / script).write_text(STAGE)
        self.w = self.root / 'workspace'
        self.w.mkdir()
        for folder in ('runs', 'labels', 'reports'):
            (self.w / folder).mkdir()
        (self.w / 'labels/mixed.txt').write_text('')
        (self.w / 'labels/conpot.json').write_text('{"schema_version":1,"events":[]}')
        (self.w / 'kube').write_text('fixture')
        self.c = dict(identity='a'*32, kubeconfig=str(self.w / 'kube'), source_layout=dict(
            state_root='/var/lib/honeypots-test', log_root='/var/log/honeypots-test', namespace='honeypots',
            mixed_release='mixed-test', conpot_release='modbus-test'))
        ctl.write(self.w / 'runtime.json', dict(state_root=self.c['source_layout']['state_root']))
        ctl.write(self.w / 'deployment.json', dict(log_root=self.c['source_layout']['log_root'],namespace='honeypots',
                  mappings=[dict(honeypot='cowrie',release='mixed-test')]))
        self.args = argparse.Namespace(mode='install', since=None)

    def tearDown(self): self.temp.cleanup()

    def run_case(self, scenario):
        (self.project / 'scenario').write_text(scenario)
        with patch.object(ctl, 'PROJECT', self.project), \
             patch.object(ctl, 'doctor', return_value={'status':'passed','checks':[]}), \
             patch.object(ctl, 'call'):
            ctl.run_workspace(self.args, self.w, self.c, dict(os.environ))

    def latest(self):
        return max((self.w / 'runs').glob('*/workflow.json'), key=lambda p: p.stat().st_mtime_ns)

    def test_install_then_upgrade_keeps_identity(self):
        self.run_case('success')
        first = ctl.read(self.w / 'reporting.json')
        self.assertEqual(first['mixed']['services'], ['cowrie'])
        self.assertEqual(ctl.read(self.latest())['status'], 'completed')
        with self.assertRaisesRegex(ValueError, 'already has a deployment'):
            self.run_case('success')
        self.args.mode = 'upgrade'
        self.run_case('success')
        self.assertEqual(first, ctl.read(self.w / 'reporting.json'))

    def test_report_failure_preserves_deployment_state(self):
        with self.assertRaisesRegex(ValueError, 'report failed'):
            self.run_case('report_failure')
        manifest = ctl.read(self.latest())
        self.assertEqual(manifest['deployment_status'], 'completed')
        self.assertEqual(manifest['status'], 'failed')
        self.assertTrue((self.w / 'reporting.json').is_file())
        self.assertTrue((self.w / 'active-deployment.json').is_file())

    def test_deployment_failure_does_not_publish_reporting(self):
        with self.assertRaisesRegex(ValueError, 'deployment failed'):
            self.run_case('deployment_failure')
        self.assertFalse((self.w / 'reporting.json').exists())
        self.assertEqual(ctl.read(self.latest())['status'], 'failed')

    def test_no_targets_preserves_active_reporting(self):
        self.run_case('success')
        previous = (self.w / 'reporting.json').read_bytes()
        self.args.mode = 'upgrade'
        self.run_case('empty')
        self.assertEqual(ctl.read(self.latest())['status'], 'no_targets')
        self.assertEqual((self.w / 'reporting.json').read_bytes(), previous)

    def test_prepare_never_deploys_or_publishes(self):
        self.args.mode = 'prepare'
        self.run_case('success')
        manifest = ctl.read(self.latest())
        self.assertEqual([s['name'] for s in manifest['stages']], ['prepare'])
        self.assertEqual(manifest['status'], 'prepared')
        self.assertFalse((self.w / 'reporting.json').exists())


if __name__ == '__main__': unittest.main()

class Schedule(unittest.TestCase):
    def test_schedule_uses_workspace_locking_entrypoint_without_install(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / 'workspace'
            workspace.mkdir()
            ctl.write(workspace / 'workspace.json', dict(schema_version=1, identity='b'*32, kubeconfig=str(root / 'kube')))
            ctl.write(workspace / 'reporting.json', {'schema_version':2, 'kubeconfig':str(root / 'kube')})
            destination = root / 'units'
            calls = []
            def fake_call(command, **kwargs):
                calls.append(command)
                if any('generate_report_units.py' in v for v in command):
                    destination.mkdir()
                    (destination / 'honeypot-report-bbbbbbbbbbbb.service').write_text('[Service]\nExecStart=old\n')
                    (destination / 'honeypot-report-bbbbbbbbbbbb.timer').write_text('[Timer]\n')
            with patch.object(sys, 'argv', ['honeypotctl.py','schedule','--workspace',str(workspace),'--output',str(destination)]), patch.object(ctl, 'call', side_effect=fake_call):
                self.assertEqual(ctl.main(), 0)
            service = (destination / 'honeypot-report-bbbbbbbbbbbb.service').read_text()
            self.assertIn('honeypotctl.py', service)
            self.assertIn('"report" "--workspace"', service)
            self.assertFalse(any(cmd[0] == 'sudo' for cmd in calls))
            self.assertEqual(calls[-1][0:2], ['systemd-analyze', 'verify'])
