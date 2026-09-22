"""Calendar boundaries, persistent configuration, and rendered timer checks."""
import json
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import report_time as rt
import honeypotctl as ctl
import generate_report_units as units

class Calendar(unittest.TestCase):
    def window(self, instant, zone='Europe/Athens'):
        return rt.day_window(zone, datetime.fromisoformat(instant))

    def test_utc_legacy(self):
        self.assertEqual(self.window('2026-09-22T12:49:16+00:00', 'UTC'),
                         ('2026-09-21T00:00:00+00:00', '2026-09-22T00:00:00+00:00'))

    def test_athens_midnight_schedule(self):
        self.assertEqual(self.window('2026-09-22T21:10:00+00:00'),
                         ('2026-09-21T21:00:00+00:00', '2026-09-22T21:00:00+00:00'))

    def test_winter_offset(self):
        self.assertEqual(self.window('2026-12-22T22:10:00+00:00'),
                         ('2026-12-21T22:00:00+00:00', '2026-12-22T22:00:00+00:00'))

    def test_dst_calendar_day_lengths(self):
        for instant, hours in [('2026-03-29T21:10:00+00:00',23),('2026-10-25T22:10:00+00:00',25)]:
            with self.subTest(instant=instant):
                start,end=map(datetime.fromisoformat,self.window(instant))
                self.assertEqual((end-start).total_seconds(), hours*3600)

    def test_current_local_day(self):
        self.assertEqual(rt.day_window('Europe/Athens',datetime.fromisoformat('2026-09-22T21:10:00+00:00'),False),
                         ('2026-09-22T21:00:00+00:00','2026-09-22T21:10:00+00:00'))

    def test_invalid_inputs(self):
        for zone in ['Unknown/Zone','Europe/Athens\nOther=true','../etc/passwd']:
            with self.subTest(zone=zone), self.assertRaises(ValueError): rt.reporting_zone(zone)
        with self.assertRaises(ValueError): rt.day_window('UTC',datetime(2026,9,22))

class Configuration(unittest.TestCase):
    def test_change_preserves_identities_and_backs_up(self):
        with tempfile.TemporaryDirectory() as temp:
            w=Path(temp);(w/'runs').mkdir()
            config=dict(schema_version=1,identity='a'*32,kubeconfig='/example/kube')
            reporting=dict(schema_version=2,mixed=dict(database_id='stable-id'))
            ctl.write(w/'workspace.json',config);ctl.write(w/'reporting.json',reporting)
            with patch.object(sys,'argv',['honeypotctl.py','set-timezone','--workspace',str(w),'--timezone','Europe/Athens']), patch.object(ctl,'call') as call:
                self.assertEqual(ctl.main(),0);call.assert_not_called()
            self.assertEqual(ctl.read(w/'workspace.json'),dict(config,timezone='Europe/Athens'))
            self.assertEqual(ctl.read(w/'reporting.json'),dict(reporting,timezone='Europe/Athens'))
            backup=next((w/'runs').glob('timezone-change-*'))
            self.assertEqual(ctl.read(backup/'workspace.json'),config)
            self.assertEqual(ctl.read(backup/'reporting.json'),reporting)

    def test_rendered_timer_uses_athens(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);config=root/'config.json'
            config.write_text(json.dumps(dict(schema_version=2,kubeconfig='/example/kube',timezone='Europe/Athens')))
            args=['generate_report_units.py','--project',str(Path(ctl.__file__).parent),'--config',str(config),'--output',str(root/'units'),'--time','00:10']
            with patch.object(sys,'argv',args),patch.object(units.subprocess,'run'):
                self.assertIsNone(units.main())
            self.assertIn('OnCalendar=*-*-* 00:10:00 Europe/Athens',(root/'units/thesis-daily-report.timer').read_text())
            args[-2]='--utc-time';args[args.index('--output')+1]=str(root/'rejected')
            with patch.object(sys,'argv',args), self.assertRaises(SystemExit) as error: units.main()
            self.assertEqual(error.exception.code,1)
            self.assertFalse((root/'rejected').exists())
