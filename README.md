# SSH Login Anomaly Analyzer

![SSH Login Anomaly Analyzer workflow](assets/workflow.svg)

Offline correlation of SSH failed-login bursts and subsequent successful authentication.

**Fresh portfolio implementation • Python 3.10+ • Standard library only**

## Run

```bash
python3 --version
python3 analyzer.py examples/auth.log --threshold 5 --window 300
python3 -m unittest discover -s tests -v
```

## Implemented behavior

- Parses sshd password failures and accepted password/publickey events with timezone-aware ISO 8601 timestamps.
- Sorts out-of-order events and uses a per-destination-host/source-IP sliding window; one burst alert per contiguous threshold episode.
- Reports successful authentication after a threshold of failures from the same IP on the same destination host; every finding includes `host`.
- Explicit ignored-line and parsed-event counts expose coverage gaps.

Host names are matched exactly as logged. Normalize host aliases upstream if needed. Missing host fields and SSH-looking text embedded in another application's message are ignored. This is per-host correlation, not detection of campaigns spread across hosts.

Timestamp boundaries are handled without terminating the run: entries whose
timezone conversion would fall outside Python's year 1–9999 UTC range are counted
as ignored lines. Valid events close to the minimum date use a saturated window
cutoff at the earliest representable UTC instant. Windows too large to represent
as a Python timedelta are rejected with a clear error (CLI exit 2), even for empty
input. These checks do not establish whether a log's timestamp is trustworthy.

Ports must be complete ASCII decimal tokens of one to five digits in the range
1–65535. Invalid ports are counted as ignored lines and do not affect findings.
Whitespace-separated suffixes such as `ssh2` remain supported.

## Multi-account failure review

```bash
python3 analyzer.py examples/auth.log --threshold 5 --window 300 --min-users 3
```

Require both five failures and three distinct failed-login usernames in the same
host/source window. The default minimum is 1, preserving existing burst behavior.
Success-after-failures findings use the same distinct-user requirement. Usernames
are matched exactly; shared NAT can combine unrelated users. This is a candidate
password-spray signal, not proof of an attack. Expired usernames stop contributing
to the threshold. Reports include the configured `min_users` value.

## Scope and limitations

Only `TIMESTAMP HOST sshd[PID]: MESSAGE` (or `sshd:` without a PID) text with an ISO 8601 timestamp is accepted (for example rsyslog RFC3339-style output); classic `Oct 12 12:00:00` logs are ignored, not assigned an invented year/timezone. Duplicates count; deduplicate upstream when necessary. Same IP does not prove same user or actor; NAT and automation cause false positives. Input capped at 20 MiB. Ties use source line order. Logs may contain personal data; only synthetic documentation-range addresses are shipped. No blocking or live journald collection.

## Validation

26 unit tests passed locally on Python 3.12.14, including minimum/maximum dates, timezone-conversion overflow, equivalent timezone instants and CLI error handling. Synthetic CLI examples were executed and results are included under `examples/`. No customer data, historical lab results or production effectiveness is claimed. CI configuration is supplied; remote CI status must be checked after publishing.

## Files

- `analyzer.py` — implementation and CLI.
- `tests/test_main.py` — regression and boundary tests.
- `examples/` — synthetic inputs and generated output.
- `assets/workflow.svg` — project-specific animation with reduced-motion support.
- `.github/workflows/ci.yml` — pinned-action CI.

## Safe operation

Use inputs and hosts you own or are authorized to assess. Review reports before publication; real files, headers and logs can contain sensitive information. These tools do not establish that a system is secure or compromised.


