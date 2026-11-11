# Security policy

## Reporting a vulnerability in netscan

Email **alaouihichamiyoussef@gmail.com** with a subject line starting
`netscan security`. Do not open a public issue for a vulnerability.

Include the affected version (`netscan --version`), a minimal reproduction, and
the impact you believe it has. Expect an acknowledgement within 72 hours. There
is no bug bounty for this project; credit is given in the changelog unless you
ask otherwise.

Areas that count as a vulnerability in the scanner:

- Memory exhaustion or an unbounded task/thread count reachable from normal
  command-line input.
- A crafted DNS response or banner that crashes the process instead of being
  recorded as an error.
- Path traversal or arbitrary file overwrite through `--output`.
- Terminal escape injection from an untrusted banner (banners are
  attacker-controlled bytes).
- Reading a report written by one user as another user through a predictable
  temp-file name.

## Using netscan against systems you do not own

`netscan` opens TCP connections. Doing that without authorisation is illegal in
most jurisdictions and is grounds for account termination with most hosting
providers. The MIT licence disclaims all liability; the responsibility is yours.

Practical guidance that the tool supports:

- `--allow-scope CIDR` restricts expansion so a scan cannot leave a range you
  were authorised for.
- `--rate-limit N` caps probes per second, which keeps you inside the "no
  disruptive traffic" clause that most bug bounty programmes impose.
- `--max-hosts` and the built-in `MAX_ADDRESSES` ceiling refuse accidental wide
  scans.

The scanner does not send exploit payloads and will not detect application
vulnerabilities. It tells you what is listening, which services those ports
usually carry, and which exposures are worth a human look.

## Supported versions

The latest minor release receives fixes. `1.x` (the single-file script) is
unsupported and will not receive security patches; upgrade to `2.x`.
