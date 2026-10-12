"""Offline, timezone-aware SSH failure-burst and subsequent-success analysis."""
import argparse
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import ipaddress
import json
from pathlib import Path
import re

PATTERN=re.compile(r'sshd(?:\[\d+\])?: (Failed password|Accepted password|Accepted publickey) for (?:invalid user )?(\S+) from (\S+) port \d+')

def parse(lines):
    events=[]; ignored=0
    for number,line in enumerate(lines,1):
        match=PATTERN.search(line)
        try:
            if not match: raise ValueError()
            stamp=datetime.fromisoformat(line.split()[0].replace('Z','+00:00'))
            if stamp.tzinfo is None: raise ValueError()
            events.append(dict(time=stamp.astimezone(timezone.utc),kind='failure' if match[1]=='Failed password' else 'success',
                               user=match[2],ip=str(ipaddress.ip_address(match[3])),line=number))
        except (ValueError,IndexError): ignored+=1
    return sorted(events,key=lambda e:(e['time'],e['line'])),ignored


def analyze(lines,threshold=5,window_seconds=300):
    if threshold<1 or window_seconds<1: raise ValueError('Threshold and window must be positive')
    events,ignored=parse(lines); queues=defaultdict(deque); alerted=set(); findings=[]
    for event in events:
        source=event['ip']; queue=queues[source]; cutoff=event['time']-timedelta(seconds=window_seconds)
        while queue and queue[0]['time']<cutoff: queue.popleft()
        if len(queue)<threshold: alerted.discard(source)
        if event['kind']=='failure':
            queue.append(event)
            if len(queue)>=threshold and source not in alerted:
                findings.append(dict(rule='FAILURE_BURST',source=source,time=event['time'].isoformat(),
                                     count=len(queue),users=sorted({e['user'] for e in queue})))
                alerted.add(source)
        elif len(queue)>=threshold:
            findings.append(dict(rule='SUCCESS_AFTER_FAILURES',source=source,user=event['user'],
                                 time=event['time'].isoformat(),count=len(queue),
                                 note='Same source IP; may involve different accounts or shared NAT. Investigate, do not assume compromise.'))
    return dict(parsed_events=len(events),ignored_lines=ignored,window_seconds=window_seconds,threshold=threshold,
                duplicate_policy='Repeated lines count as repeated events; deduplicate upstream if appropriate.',findings=findings)


def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('log',type=Path)
    p.add_argument('--threshold',type=int,default=5); p.add_argument('--window',type=int,default=300)
    args=p.parse_args()
    try:
        if args.log.stat().st_size>20*1024*1024: raise ValueError('Input exceeds 20 MiB limit')
        print(json.dumps(analyze(args.log.read_text(errors='replace').splitlines(),args.threshold,args.window),indent=2))
    except (OSError,ValueError) as exc: p.exit(2,str(exc)+'\n')
if __name__=='__main__': main()
