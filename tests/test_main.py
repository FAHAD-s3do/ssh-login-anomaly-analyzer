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
