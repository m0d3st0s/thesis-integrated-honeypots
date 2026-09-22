"""Use the inspected image's packet code; no container/network is simulated."""
import ast
import base64
import importlib
import importlib.util
import io
import json
import logging
import struct
import subprocess
import sys
import tempfile
import types
import unittest
import warnings
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from prepare_protocol_chart import prepare
from smb_repair_chart import repair_assets
import test_protocols

SCRIPT = PROJECT / 'assets/dionaea-smb/repair.py'
spec = importlib.util.spec_from_file_location('smb_image_repair', SCRIPT)
repair_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repair_module)
FIXTURE = PROJECT / 'tests/fixtures/dionaea-smb/source.zip.b64'


class SmbRepair(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        with zipfile.ZipFile(io.BytesIO(base64.b64decode(FIXTURE.read_bytes()))) as archive:
            self.sources = {name: archive.read(name) for name in archive.namelist()}
        self.original = self.sources['smbfields.py']

    def load_packet_code(self, fixed):
        root = self.root / ('fixed' if fixed else 'original')
        root.mkdir()
        for name, data in self.sources.items():
            if name == 'smbfields.py' and fixed:
                data = repair_module.repair(data)
            (root / name).write_bytes(data)
        name = '_smb_fixture_' + root.name
        package = types.ModuleType(name)
        package.__path__ = [str(root)]
        sys.modules[name] = package
        self.addCleanup(lambda: [sys.modules.pop(n, None) for n in list(sys.modules)
                                 if n == name or n.startswith(name + '.')])
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', SyntaxWarning)
            fields = importlib.import_module(name + '.smbfields')
        tree = ast.parse(self.sources['smb.py'])
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'smbd')
        method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'process')
        namespace = dict(vars(fields), smblog=logging.getLogger('test.smb'))
        # Execute the real process method. No fake response implementation.
        exec(compile(ast.Module(body=[method], type_ignores=[]), 'image-smb.py', 'exec'), namespace)
        instance = types.SimpleNamespace(config=types.SimpleNamespace(
            oem_domain_name='WORKGROUP', server_name='LAB'), state={})
        return fields, lambda p: namespace['process'](instance, p)

    def negotiate(self, fields, extended):
        # Exact SMB1 Nmap request from the failed lab trace.
        raw = bytes.fromhex('00000031ff534d42720000000018456800000000000000000000000000005b04'
                            '00000100000e00024e54204c4d20302e3132000200')
        p = fields.NBTSession(raw)
        if not extended:
            p[fields.SMB_Header].Flags2 &= ~fields.SMB_FLAGS2_EXT_SEC
        return p

    def test_original_handler_reproduces_reported_keyerror(self):
        fields, process = self.load_packet_code(False)
        with self.assertRaisesRegex(KeyError, 'OemDomainName'):
            process(self.negotiate(fields, True))

    def test_repaired_handler_serializes_valid_smb1_negotiate_responses(self):
        fields, process = self.load_packet_code(True)
        for extended in (True, False):
            with self.subTest(extended=extended):
                raw = process(self.negotiate(fields, extended)).build()
                self.assertEqual(int.from_bytes(raw[1:4], 'big'), len(raw) - 4)
                self.assertEqual(raw[4:9], b'\xffSMB\x72')
                self.assertEqual(raw[9:13], b'\0' * 4)
                self.assertTrue(raw[13] & 0x80)
                self.assertEqual(struct.unpack_from('<H', raw, 34)[0], 1)
                self.assertEqual(raw[36], 17)
                self.assertEqual(struct.unpack_from('<H', raw, 37)[0], 0)
                self.assertEqual(struct.unpack_from('<H', raw, 71)[0], len(raw) - 73)
                capabilities = struct.unpack_from('<I', raw, 56)[0]
                self.assertEqual(bool(capabilities & fields.CAP_EXTENDED_SECURITY), extended)

    def test_repair_rejects_unrecognized_source(self):
        with self.assertRaisesRegex(ValueError, 'Unrecognized'):
            repair_module.repair(self.original + b'\n')
        with self.assertRaisesRegex(ValueError, 'Unrecognized'):
            repair_module.repair(repair_module.repair(self.original))

    def test_init_script_keeps_original_and_refuses_mismatch_without_overwrite(self):
        source = self.root / 'smbfields.py'
        source.write_bytes(self.original)
        output = self.root / 'volume/smbfields.py'
        command = [sys.executable, str(SCRIPT), '--source', str(source), '--output', str(output)]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(source.read_bytes(), self.original)
        self.assertEqual(output.read_bytes(), repair_module.repair(self.original))
        source.write_bytes(self.original + b'\n')
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_bytes(), repair_module.repair(self.original))

    def prepare_fixture(self, services):
        req = test_protocols.request(services)
        chart = self.root / 'protocol-mixed'
        (chart / 'templates').mkdir(parents=True)
        text = test_protocols.Recipes().template(req)
        (chart / 'templates/deployment.yaml').write_text(text)
        reqpath = self.root / 'request.json'
        reqpath.write_text(json.dumps(req))
        with redirect_stdout(io.StringIO()):
            prepare(chart, reqpath, self.root / 'state', 'test-node')
        return chart

    def test_chart_mounts_checked_source_using_same_pinned_image(self):
        chart = self.prepare_fixture(['http', 'https', 'smb', 'ssh'])
        text = (chart / 'templates/deployment.yaml').read_text()
        self.assertIn('name: repair-dionaea-smb1', text)
        self.assertIn('{{ .Values.honeypots.dionaea.image.repository }}:{{ .Values.honeypots.dionaea.image.tag }}', text)
        self.assertIn('subPath: smbfields.py\n              readOnly: true', text)
        self.assertIn('mountPath: ' + repair_module.SOURCE, text)
        self.assertIn('emptyDir: {}', text)
        self.assertEqual((chart / 'files/dionaea-smb/repair.py').read_bytes(), SCRIPT.read_bytes())
        self.assertIn('.Files.Get "files/dionaea-smb/repair.py"',
                      (chart / 'templates/dionaea-smb-repair.yaml').read_text())
        self.assertFalse((self.root / 'state').exists())

    def test_chart_without_smb_has_no_repair(self):
        chart = self.prepare_fixture(['http', 'https', 'ssh'])
        self.assertNotIn('repair-dionaea', (chart / 'templates/deployment.yaml').read_text())
        self.assertFalse((chart / 'templates/dionaea-smb-repair.yaml').exists())

    def test_changed_repair_asset_is_refused(self):
        assets = self.root / 'assets'
        assets.mkdir()
        (assets / 'manifest.json').write_bytes((SCRIPT.parent / 'manifest.json').read_bytes())
        (assets / 'repair.py').write_bytes(SCRIPT.read_bytes() + b'\n')
        with patch('smb_repair_chart.ASSETS', assets):
            with self.assertRaisesRegex(ValueError, 'checksum'):
                repair_assets(self.root / 'chart')
