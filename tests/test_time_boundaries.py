import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from analyzer import analyze


def entry(stamp):
    return f'{stamp} host sshd[1]: Failed password for demo from 192.0.2.1 port 22 ssh2'


class TimeBoundaryTests(unittest.TestCase):
    def test_earliest_utc_event_does_not_underflow(self):
        report=analyze([entry('0001-01-01T00:00:00Z'),entry('0001-01-01T00:00:01Z')],2)
        self.assertEqual(report['findings'][0]['count'],2)

    def test_timezone_conversion_overflow_is_ignored(self):
        logs=[entry('0001-01-01T00:00:00+01:00'),entry('9999-12-31T23:59:59-01:00'),entry('2026-01-01T00:00:00Z')]
        report=analyze(logs)
        self.assertEqual(report['ignored_lines'],2)
        self.assertEqual(report['parsed_events'],1)

    def test_latest_utc_event_is_valid(self):
        report=analyze([entry('9999-12-31T23:59:59Z')],1)
        self.assertEqual(report['parsed_events'],1)
        self.assertEqual(len(report['findings']),1)

    def test_unrepresentable_window_rejected_even_without_events(self):
        with self.assertRaisesRegex(ValueError,'Window exceeds'):
            analyze([],window_seconds=10**30)

    def test_timezone_equivalent_events_share_window(self):
        report=analyze([entry('2026-01-01T05:00:00+05:00'),entry('2026-01-01T00:00:00Z')],2,1)
        self.assertEqual(report['findings'][0]['count'],2)

    def test_cli_boundary_input_and_huge_window(self):
        script=Path(__file__).resolve().parents[1]/'analyzer.py'
        with tempfile.TemporaryDirectory() as directory:
            log=Path(directory)/'auth.log'
            log.write_text(entry('0001-01-01T00:00:00Z'))
            def run(*args):
                return subprocess.run([sys.executable,str(script),str(log),*args],capture_output=True,text=True)
            valid=run('--threshold','1')
            self.assertEqual(valid.returncode,0,valid.stderr)
            self.assertEqual(json.loads(valid.stdout)['parsed_events'],1)
            invalid=run('--window',str(10**30))
            self.assertEqual(invalid.returncode,2)
            self.assertNotIn('Traceback',invalid.stderr)
