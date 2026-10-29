import unittest
from analyzer import analyze


class DistinctUserTests(unittest.TestCase):
    def line(self, user, second=0, host='host'):
        return f'2026-10-29T00:00:{second:02d}Z {host} sshd[1]: Failed password for {user} from 192.0.2.1 port 22'

    def test_single_account_burst_filtered(self):
        self.assertEqual(analyze([self.line('a')]*5,min_users=3)['findings'],[])

    def test_alert_when_distinct_threshold_reached(self):
        r=analyze([self.line(u) for u in ('a','a','a','b','c')],min_users=3)
        self.assertEqual(len(r['findings']),1)
        self.assertEqual(r['findings'][0]['users'],['a','b','c'])

    def test_hosts_do_not_share_users(self):
        lines=[self.line('a')]*5+[self.line('b',host='other')]*5
        self.assertEqual(analyze(lines,min_users=2)['findings'],[])

    def test_expiration_rearms_episode(self):
        lines=[self.line(u) for u in ('a','b')]+[self.line(u,10) for u in ('a','c')]
        self.assertEqual(len(analyze(lines,threshold=2,window_seconds=5,min_users=2)['findings']),2)

    def test_invalid_minimum(self):
        for value in (0,-1,True,1.5):
            with self.assertRaises(ValueError): analyze([],min_users=value)
