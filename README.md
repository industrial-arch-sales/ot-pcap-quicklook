# OT PCAP Quicklook

Dependency-free local triage for classic PCAP files and OT-security logs. It provides a quick terminal summary of IPv4/TCP conversations, Modbus TCP function codes and potential write commands, plus basic MQTT packet types on port 1883.

Built for industrial cybersecurity engineers, OT pentesters, and IEC 62443 assessment teams who need a fast first look before deeper analysis.

## Quick start

```bash
git clone https://github.com/industrial-arch-sales/ot-pcap-quicklook.git
cd ot-pcap-quicklook
python3 main.py ./capture.pcap
```

For a text log:

```bash
python3 main.py ./sensor.log
```

Limit an unusually large capture:

```bash
python3 main.py ./capture.pcap --max-packets 50000
```

## What it reports

- Top observed IPv4/TCP conversations
- Modbus TCP function codes and Unit IDs
- Potential Modbus write functions: `0x05`, `0x06`, `0x0F`, `0x10`, `0x16`, `0x17`
- Basic MQTT control-packet types when TCP port `1883` is observed
- Simple keyword counts for text logs

## Local edition scope

This repository is a small, read-only static triage utility. It has no third-party dependencies and intentionally does **not** provide:

- executive or formal PDF reports;
- policy enforcement, maintenance-window validation, asset whitelisting, or compliance conclusions;
- TCP stream reassembly, decryption, PCAPNG support, or a complete protocol decoder;
- continuous monitoring, incident-response evidence handling, or a replacement for analyst validation.

Treat output as an initial observation, not proof of an incident or a security finding.

## Need an assessment-ready report?

For structured findings, Modbus write-command analysis, policy context, and SHA-256 traceability designed for client-facing OT assessments, use **[SXT Systems OT Security Engine](https://ot.sxtsystems.com.br)**.

See a [synthetic Modbus report sample](https://ot.sxtsystems.com.br/sample-report.pdf).

## Supported input

| Input | Support |
|---|---|
| Classic libpcap (`.pcap`, `.cap`) | Ethernet, IPv4, TCP static inspection |
| PCAPNG | Not supported |
| Text files | Keyword-based summary |

## Requirements

Python 3.10 or newer. No package installation is needed.

## Repository metadata

**Suggested repository name:** `ot-pcap-quicklook`

**Suggested GitHub description:** `Dependency-free Modbus TCP and MQTT PCAP quick-look CLI for OT/ICS security triage.`

**Suggested topics:** `ics-security`, `ot-security`, `ot-cybersecurity`, `industrial-cybersecurity`, `modbus`, `modbus-tcp`, `modbus-parser`, `pcap`, `pcap-analysis`, `mqtt`, `iec-62443`, `ics-pentesting`, `industrial-control-systems`, `scada-security`, `python`

## License

MIT.
