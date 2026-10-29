"""Offline, timezone-aware SSH failure-burst and subsequent-success analysis."""
import argparse
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import ipaddress
import json
from pathlib import Path
import re

PATTERN=re.compile(r'^(?P<stamp>\S+)\s+(?P<host>\S+)\s+sshd(?:\[\d+\])?: (?P<action>Failed password|Accepted password|Accepted publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\S+)(?:\s|$)')

def parse(lines):
    events=[]; ignored=0
    for number,line in enumerate(lines,1):
        match=PATTERN.search(line)
        try:
            if not match: raise ValueError()
            port=match['port']
            if (not port or len(port)>5 or any(c not in '0123456789' for c in port)
                    or not 1 <= int(port) <= 65535): raise ValueError()
            stamp=datetime.fromisoformat(match['stamp'].replace('Z','+00:00'))
            if stamp.tzinfo is None: raise ValueError()
            events.append(dict(time=stamp.astimezone(timezone.utc),kind='failure' if match['action']=='Failed password' else 'success',
                               host=match['host'],user=match['user'],ip=str(ipaddress.ip_address(match['ip'])),line=number))
        except (ValueError,IndexError,OverflowError): ignored+=1
    return sorted(events,key=lambda e:(e['time'],e['line'])),ignored


def analyze(lines,threshold=5,window_seconds=300,min_users=1):
    if type(min_users) is not int or min_users<1: raise ValueError('Minimum users must be a positive integer')
    if threshold<1 or window_seconds<1: raise ValueError('Threshold and window must be positive')
    try:
        window=timedelta(seconds=window_seconds)
    except OverflowError as exc:
        raise ValueError('Window exceeds supported datetime range') from exc
    earliest=datetime.min.replace(tzinfo=timezone.utc)
    events,ignored=parse(lines); queues=defaultdict(deque); alerted=set(); findings=[]
    for event in events:
        source=event['ip']; host=event['host']; key=(host,source); queue=queues[key]
        try:
            cutoff=event['time']-window
        except OverflowError:
            # No representable event can be older than the minimum UTC date.
            cutoff=earliest
        while queue and queue[0]['time']<cutoff: queue.popleft()
        if len(queue)<threshold or len({e['user'] for e in queue})<min_users: alerted.discard(key)
        if event['kind']=='failure':
            queue.append(event)
            if len(queue)>=threshold and len({e['user'] for e in queue})>=min_users and key not in alerted:
                findings.append(dict(rule='FAILURE_BURST',source=source,host=host,time=event['time'].isoformat(),
                                     count=len(queue),users=sorted({e['user'] for e in queue})))
                alerted.add(key)
        elif len(queue)>=threshold and len({e['user'] for e in queue})>=min_users:
            findings.append(dict(rule='SUCCESS_AFTER_FAILURES',source=source,host=host,user=event['user'],
                                 time=event['time'].isoformat(),count=len(queue),
                                 note='Same destination host and source IP; may involve different accounts or shared NAT. Investigate, do not assume compromise.'))
    return dict(parsed_events=len(events),ignored_lines=ignored,window_seconds=window_seconds,threshold=threshold,min_users=min_users,
                duplicate_policy='Repeated lines count as repeated events; deduplicate upstream if appropriate.',findings=findings)


def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('log',type=Path)
    p.add_argument('--threshold',type=int,default=5); p.add_argument('--window',type=int,default=300)
    p.add_argument('--min-users',type=int,default=1,help='Require this many distinct failed-login usernames per host/source window')
    args=p.parse_args()
    try:
        if args.log.stat().st_size>20*1024*1024: raise ValueError('Input exceeds 20 MiB limit')
        print(json.dumps(analyze(args.log.read_text(errors='replace').splitlines(),args.threshold,args.window,args.min_users),indent=2))
    except (OSError,ValueError) as exc: p.exit(2,str(exc)+'\n')
if __name__=='__main__': main()


