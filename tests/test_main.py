import unittest
from analyzer import analyze

def line(second,kind='Failed password',ip='192.0.2.1',minute=0):return f'2026-01-01T00:{minute:02}:{second:02}Z host sshd[1]: {kind} for demo from {ip} port 22 ssh2'
class Tests(unittest.TestCase):
 def test_burst(self):self.assertEqual(len(analyze([line(i) for i in range(5)])['findings']),1)
 def test_success_after_burst(self):self.assertEqual(analyze([line(i) for i in range(5)]+[line(6,'Accepted publickey')])['findings'][-1]['rule'],'SUCCESS_AFTER_FAILURES')
 def test_window_expires(self):self.assertEqual(analyze([line(i) for i in range(4)]+[line(0,minute=6)])['findings'],[])
 def test_out_of_order(self):self.assertEqual(analyze([line(i) for i in reversed(range(5))])['findings'][0]['count'],5)
 def test_sources_separate(self):self.assertEqual(analyze([line(i,ip=f'192.0.2.{i+1}') for i in range(5)])['findings'],[])
 def test_reject_naive_timestamp(self):self.assertEqual(analyze([line(1).replace('Z','')])['ignored_lines'],1)
 def test_window_boundary(self):self.assertEqual(len(analyze([line(0),line(0,minute=5)],2,300)['findings']),1)


class HostIsolationTests(unittest.TestCase):
 def host_line(self, second, host, kind='Failed password'):
  return line(second,kind).replace(' host sshd',f' {host} sshd')
 def test_failures_on_different_hosts_do_not_combine(self):
  logs=[self.host_line(i,'alpha' if i<3 else 'beta') for i in range(5)]
  self.assertEqual(analyze(logs)['findings'],[])
 def test_success_on_other_host_does_not_correlate(self):
  logs=[self.host_line(i,'alpha') for i in range(5)]+[self.host_line(6,'beta','Accepted password')]
  self.assertEqual([f['rule'] for f in analyze(logs)['findings']],['FAILURE_BURST'])
 def test_each_host_has_independent_alert_state(self):
  logs=[self.host_line(i,h) for i in range(6) for h in ('alpha','beta')]
  findings=analyze(logs)['findings']
  self.assertEqual(len(findings),2)
  self.assertEqual({f['host'] for f in findings},{'alpha','beta'})
 def test_same_host_success_retains_host(self):
  logs=[self.host_line(i,'alpha') for i in range(5)]+[self.host_line(6,'alpha','Accepted publickey')]
  self.assertEqual(analyze(logs)['findings'][-1]['host'],'alpha')
 def test_missing_host_and_embedded_sshd_message_are_ignored(self):
  logs=[line(0).replace(' host sshd',' sshd'),line(1).replace('host sshd[1]:','host app[1]: sshd[1]:')]
  result=analyze(logs)
  self.assertEqual(result['parsed_events'],0)
  self.assertEqual(result['ignored_lines'],2)
