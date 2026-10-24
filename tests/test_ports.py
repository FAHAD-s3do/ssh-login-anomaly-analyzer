import unittest
from analyzer import analyze, parse


class PortTests(unittest.TestCase):
    def line(self, port):
        return f'2026-10-24T00:00:00Z host sshd[1]: Failed password for user from 192.0.2.1 port {port}'

    def test_valid_boundaries_and_suffix(self):
        for port in ('1', '65535', '22 ssh2'):
            with self.subTest(port=port):
                events, ignored = parse([self.line(port)])
                self.assertEqual(len(events), 1)
                self.assertEqual(ignored, 0)

    def test_invalid_ports_are_ignored(self):
        for port in ('0', '65536', '-1', '22junk', '22.0', '２２', '9'*5000):
            with self.subTest(port=port):
                events, ignored = parse([self.line(port)])
                self.assertEqual(events, [])
                self.assertEqual(ignored, 1)

    def test_invalid_port_cannot_trigger_burst(self):
        result = analyze([self.line('22junk')] * 5)
        self.assertEqual(result['findings'], [])
        self.assertEqual(result['ignored_lines'], 5)
