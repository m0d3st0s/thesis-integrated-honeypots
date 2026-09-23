"""Descriptive profiling and separation from planning; fixture scans, no network."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from profiler_v3 import profile_scan
from reconcile_profiles import reconcile
from build_plan_v2 import build_plan
from build_requests import make_requests


def port(number, name, extra='', child='', state='open', method='probed'):
    return (f'<port protocol="tcp" portid="{number}"><state state="{state}"/>'
            f'<service name="{name}" method="{method}" {extra}>{child}</service></port>')


def xml(ports, metadata='', start=1):
    return (f'<nmaprun start="{start}"><host><status state="up"/>'
            '<address addr="192.0.2.20" addrtype="ipv4"/>' + metadata + '<ports>' + ports +
            f'</ports></host><runstats><finished exit="success" time="{start+1}"/></runstats></nmaprun>')


class DeviceProfiles(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / 'service-catalog.json').write_bytes((PROJECT / 'config/service-catalog.json').read_bytes())

    def tearDown(self):
        self.temp.cleanup()

    def scan(self, ports, metadata=''):
        (self.root / 'services.xml').write_text(xml(ports, metadata))
        (self.root / 'scan-manifest.json').write_text(json.dumps(dict(status='completed',
            discovered_targets=['192.0.2.20'], profiles=[dict(kind='general',source_xml='services.xml')])))
        return profile_scan(self.root/'services.xml',self.root/'service-catalog.json')['devices'][0]['device_profile']

    def test_linux_with_multiple_roles_and_cpe_provenance(self):
        p = self.scan(port(22,'ssh','ostype="Linux"', '<cpe>cpe:/o:linux:linux_kernel</cpe>') + port(80,'http'))
        self.assertEqual(p['os_family'], 'linux')
        self.assertEqual(p['roles'], ['ssh_server','web_server'])
        self.assertEqual(p['os_assessment']['status'], 'inferred')
        self.assertTrue(all(e['xml_path'] and e['source_index']==0 for e in p['os_assessment']['evidence']))
        r = reconcile(self.root)['devices'][0]
        self.assertEqual(r['observations'][0]['service_cpes'], ['cpe:/o:linux:linux_kernel'])

    def test_no_evidence_no_guessed_os_or_roles(self):
        p=self.scan(port(22,'ssh',method='table')+port(80,'http',state='closed'))
        self.assertEqual(p['os_family'],'unknown')
        self.assertEqual(p['os_assessment']['status'],'no_evidence')
        self.assertEqual(p['roles'],[])

    def test_os_conflict_does_not_block_confirmed_service_plan(self):
        self.scan(port(22,'ssh','ostype="Linux"')+port(80,'http','ostype="Windows"'))
        r=reconcile(self.root)
        p=r['devices'][0]['device_profile']
        self.assertEqual(p['os_family'],'unknown')
        self.assertEqual(p['os_assessment']['status'],'conflicting_evidence')
        self.assertEqual(r['status'],'ready_for_planning')
        self.assertEqual(build_plan(self.root,PROJECT/'config/lab-deployment.json')['status'],'planned')

    def test_generic_unix_and_linux_are_compatible(self):
        p=self.scan(port(22,'ssh','ostype="Unix"')+port(80,'http','ostype="Linux"'))
        self.assertEqual(p['os_family'],'linux')

    def test_application_cpe_product_mac_and_hostname_do_not_set_os(self):
        p=self.scan(port(80,'http','product="Windows Server"', '<cpe>cpe:/a:microsoft:iis:10</cpe>'),
                    '<address addr="08:00:27:00:00:01" addrtype="mac" vendor="Oracle"/>'
                    '<hostnames><hostname name="windows-plc" type="PTR"/></hostnames>')
        self.assertEqual(p['os_family'],'unknown')
        self.assertEqual(p['physical_device_type'],'undetermined')
        self.assertEqual(len(p['identity_observations'][0]['evidence']['addresses']),2)

    def test_unknown_structured_os_hint_is_preserved(self):
        p=self.scan(port(22,'ssh','ostype="MysteryOS"'))
        self.assertEqual(p['os_assessment']['status'],'unrecognized_evidence')
        self.assertEqual(p['os_assessment']['evidence'][0]['value'],'MysteryOS')

    def test_os_fingerprint_accuracy_is_preserved_not_probability(self):
        metadata='<os><osmatch name="Linux 5.x" accuracy="96"><osclass osfamily="Linux" accuracy="96" vendor="Linux" type="general purpose"/></osmatch></os>'
        p=self.scan(port(22,'ssh'),metadata)
        self.assertEqual(p['os_family'],'linux')
        self.assertEqual(p['os_assessment']['evidence'][0]['attributes']['accuracy'],'96')
        self.assertEqual(p['os_assessment']['confidence'],'not_calibrated')

    def test_roles_do_not_require_supported_honeypot_mapping(self):
        p=self.scan(port(21,'ftp'))
        self.assertEqual(p['roles'],['ftp_server'])
        # Unsupported deployment remains review-required; classification cannot authorize it.
        self.assertEqual(build_plan(self.root,PROJECT/'config/lab-deployment.json')['status'],'review_required')

    def test_http_https_merge_to_one_role_with_both_endpoints(self):
        p=self.scan(port(80,'http')+port(8443,'http','tunnel="ssl"'))
        self.assertEqual(p['roles'],['web_server'])
        self.assertEqual(len(p['role_evidence']['web_server']),2)

    def test_smb_requires_probe_does_not_imply_windows(self):
        self.scan(port(445,'microsoft-ds'))
        self.assertEqual(reconcile(self.root)['devices'][0]['device_profile']['roles'],[])
        script='<hostscript><script id="smb-protocols"><table key="dialects"><elem>3:1:1</elem></table></script></hostscript>'
        (self.root/'smb.xml').write_text(xml(port(445,'microsoft-ds',method='table'),script,3))
        manifest=json.loads((self.root/'scan-manifest.json').read_text())
        manifest['profiles'].append(dict(kind='smb',source_xml='smb.xml',port=445))
        (self.root/'scan-manifest.json').write_text(json.dumps(manifest))
        p=reconcile(self.root)['devices'][0]['device_profile']
        self.assertEqual(p['roles'],['smb_server'])
        self.assertEqual(p['os_family'],'unknown')
        self.assertEqual(p['role_evidence']['smb_server'][0]['source_index'],1)

    def test_modbus_identification_does_not_imply_plc(self):
        self.scan(port(1502,'modbus'))
        path=self.root/'services.xml'
        script='<script id="modbus-discover"><table key="sid 0x1"><elem key="Device identification">Lab Simulator</elem></table></script>'
        path.write_text(path.read_text().replace('</port>',script+'</port>'))
        p=reconcile(self.root)['devices'][0]['device_profile']
        self.assertEqual(p['roles'],['modbus_endpoint'])
        self.assertEqual(p['physical_device_type'],'undetermined')

    def test_cross_scan_os_hints_and_endpoint_conflict(self):
        self.scan(port(445,'http','ostype="Linux"'))
        script='<hostscript><script id="smb-protocols"><table key="dialects"><elem>3.1.1</elem></table></script></hostscript>'
        (self.root/'smb.xml').write_text(xml(port(445,'microsoft-ds','ostype="Windows"'),script,3))
        manifest=json.loads((self.root/'scan-manifest.json').read_text())
        manifest['profiles'].append(dict(kind='smb',source_xml='smb.xml',port=445))
        (self.root/'scan-manifest.json').write_text(json.dumps(manifest))
        r=reconcile(self.root)
        self.assertEqual(r['status'],'review_required')
        p=r['devices'][0]['device_profile']
        self.assertEqual(p['os_assessment']['status'],'conflicting_evidence')
        self.assertEqual(p['roles'],[])
        self.assertEqual({e['source_index'] for e in p['os_assessment']['evidence']},{0,1})

    def test_classification_cannot_change_plan_or_requests(self):
        self.scan(port(22,'ssh','ostype="Linux"')+port(80,'http'))
        original=reconcile(self.root)
        baseline=build_plan(self.root,PROJECT/'config/lab-deployment.json')
        variants=[]
        changed=copy.deepcopy(original)
        changed['devices'][0]['device_profile']=dict(os_family='windows',roles=['router','plc'],recommendations=['deploy-everything'])
        changed['devices'][0]['device_type']='router'
        changed['devices'][0]['profile']='different descriptive name'
        variants.append(changed)
        removed=copy.deepcopy(original)
        del removed['devices'][0]['device_profile']
        variants.append(removed)
        for variant in variants:
            with patch('build_plan_v2.reconcile',return_value=variant):
                actual=build_plan(self.root,PROJECT/'config/lab-deployment.json')
            self.assertEqual(make_requests(actual),make_requests(baseline))
            actual.pop('generated_at'); expected=copy.deepcopy(baseline);expected.pop('generated_at')
            self.assertEqual(actual,expected)

    def test_saved_profile_edits_are_not_used_for_planning(self):
        self.scan(port(22,'ssh'))
        (self.root/'services-profile.json').write_text('{"device_profile":{"roles":["plc"]}}')
        self.assertEqual(build_plan(self.root,PROJECT/'config/lab-deployment.json')['planned_service_count'],1)

    def test_offline_command_writes_new_output_and_refuses_overwrite(self):
        self.scan(port(22,'ssh','ostype="Linux"'))
        out=self.root/'description'
        command=[sys.executable,str(PROJECT/'describe_devices.py'),'--evidence',str(self.root),'--output',str(out)]
        subprocess.run(command,check=True,capture_output=True)
        self.assertIn('OS family: linux',(out/'device-profiles.txt').read_text())
        before=(out/'device-profiles.json').read_bytes()
        self.assertNotEqual(subprocess.run(command,capture_output=True).returncode,0)
        self.assertEqual((out/'device-profiles.json').read_bytes(),before)


if __name__ == '__main__':
    unittest.main()
