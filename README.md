# xniffer

> A modular network traffic analyzer that turns packets into **explainable security findings**.

`xniffer` captures live traffic or reads a pcap, decodes it, analyzes it, and
reports security-relevant observations. Every observation it reports carries the
packet indices that produced it, the measured values next to the thresholds they
crossed, and the benign explanations it could not rule out.

```text
Network traffic  ->  Capture  ->  Decode  ->  Analyze  ->  Security findings
```

---

## Why another sniffer

It is not trying to be Wireshark, Zeek or Suricata. Those tools are excellent at
what they do. `xniffer` occupies a narrower space: **making a security read on
traffic that a human can actually check.**

Three things shape the design.

**Findings are traceable.** A finding is not an alert that asks for trust. It
cites the exact capture indices behind it, so the raw packets are always one
command away:

```bash
xniffer explain capture.pcap --id F-003   # the full reasoning
xniffer packet capture.pcap --id 142      # the packet it points at
```

**Detections are declarative.** Rules live in YAML with documented thresholds,
not buried in Python. Adding a detection does not mean touching the engine, and
reading a rule does not mean reading code.

**Privacy is the default.** Packet capture means handling other people's data.
`xniffer` masks credential material in payloads unless you explicitly opt out,
records who authorised a capture, and never sends anything anywhere — no
telemetry, no lookups, no network egress of its own.

That last point pays for itself twice: the same pass that masks a password is
what lets `xniffer` report *"credentials crossed this link in cleartext"*
without ever storing the password.

---

## Status

**Under active development.** The data model, packaging and utility layers are
in place. Capture, decoding, analysis, the rule engine and the CLI are being
built on top of them.

Follow the [roadmap](#roadmap) below for what is done and what is next.

---

## Architecture

Each layer depends only on the ones above it, and Scapy appears in exactly one
of them:

```text
model/    frozen dataclasses -- the contract every other layer speaks
util/     pure helpers (entropy, redaction, IP/port classification, statistics)
capture/  the ONLY place Scapy is imported; yields PacketRecord objects
decode/   protocol decoders, pure field-dict producers
analyze/  bounded stateful trackers (flows, hosts, DNS, time windows)
detect/   YAML-driven rule engine producing Finding objects
report/   rich terminal, JSONL and Markdown renderers
cli/      Typer command-line entry points
```

Confining Scapy to `capture/` is a deliberate constraint rather than a stylistic
one. It means the analysis and detection layers can be unit-tested by
constructing `PacketRecord` objects directly — no network interface, no root, no
pcap fixtures — and it means the decoding backend could be replaced without
touching a single detection rule.

Analysis state is **bounded**. Flows retain counters, a capped list of packet
indices for evidence, and a capped ring of timestamps — never packets. A capture
running for hours does not grow without limit.

---

## Installation

```bash
git clone https://github.com/whitexudan15/CodeAlpha_NetworkSniffer.git
cd CodeAlpha_NetworkSniffer
python3 -m venv venv
./venv/bin/pip install -e ".[dev]"
```

Reading pcap files needs no special privileges. Live capture needs
`CAP_NET_RAW`, which normally means running under `sudo`.

---

## Roadmap

- [x] **Foundation** — packaging, data model, pure utility layer
- [ ] **Capture** — live interface and pcap sources, interface discovery
- [ ] **Decode** — Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP, DNS, TLS, HTTP
- [ ] **Analyze** — flow table, host profiles, DNS map, sliding windows
- [ ] **Detect** — YAML rule engine, detection rule set, ATT&CK mapping
- [ ] **Report** — Rich terminal, JSONL, Markdown investigation report
- [ ] **CLI** — `capture`, `analyze`, `packet`, `findings`, `explain`, `rules`
- [ ] **Quality** — unit tests, golden-file reproducibility, CI

---

## Authorized use only

Packet capture exposes other people's data, and doing it without authorisation
is unlawful in most jurisdictions.

Use `xniffer` only on:

- networks you own;
- networks where you have **explicit written authorisation**;
- isolated laboratories and CTF environments;
- controlled educational environments.

`xniffer` supports this with an `--authorized-by` flag that records the
authority for a capture in its provenance metadata. The tool cannot verify what
you put there — recording it is meant to make the question part of the workflow.

---

## License

[MIT](LICENSE) © whitexudan15

---

*Built as part of the CodeAlpha cybersecurity internship program (Task 1:
Network Sniffer), developed considerably past the original brief.*
