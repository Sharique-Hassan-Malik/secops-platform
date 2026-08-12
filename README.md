# Security & Reverse Engineering

Offensive, defensive and forensic security: side-channel and acoustic attacks, supply-chain scanners, network intrusion detection and fuzzing, steganography and zip-bomb detection, browser fingerprinting, and a SIEM dashboard.

A collection of 11 self-contained projects. Each lives in its own subdirectory with its own `README.md` and `LICENSE` (most also include an `ARCHITECTURE.md` and a test suite), and can be built and run independently.

## Projects

| project | what it is |
|---|---|
| [`Acoustic-Keylogger`](./Acoustic-Keylogger) | A demonstration of an acoustic side-channel attack on a keyboard using minimal hardware. |
| [`BGP-Hijack-Analyzer`](./BGP-Hijack-Analyzer) | Parse BGP routing table dumps from RIPE NCC or RouteViews, build a historical baseline and detect anomalous route announcements — prefix hijacks, s… |
| [`Browser-Fingerprinting`](./Browser-Fingerprinting) | A research platform that collects browser fingerprint signals from real or synthetic browsers, measures the Shannon entropy contribution of each si… |
| [`Bytecode_Analyzer`](./Bytecode_Analyzer) | Decompiles .pyc files, detects obfuscation patterns and reconstructs readable Python source — without executing any user-controlled code. |
| [`CAN-IDS`](./CAN-IDS) | Anomaly detection on Controller Area Network (CAN) traffic captured via OBD-II or SocketCAN. |
| [`Pickle_Scanner`](./Pickle_Scanner) | Static analysis of pickle bytecode to detect dangerous opcodes in .pkl, .pickle, .pt and .pth files — without executing any of the payload. |
| [`Protocol_Fuzzer`](./Protocol_Fuzzer) | A mutation-based fuzzer for HTTP, DNS and MQTT. |
| [`Side-Channel-AES-Demo`](./Side-Channel-AES-Demo) | Simulates a Correlation Power Analysis (CPA) attack against an AES-128 implementation and demonstrates two countermeasures — Boolean masking and sh… |
| [`SIEM-Dashboard`](./SIEM-Dashboard) | A full-stack Security Information and Event Management dashboard that ingests log data from Apache, Nginx, syslog and iptables firewall sources in… |
| [`Steganography-Detector`](./Steganography-Detector) | Detects hidden data in images and audio files using four independent statistical methods. |
| [`Zipbomb-Detector`](./Zipbomb-Detector) | A multi-language static analysis framework for detecting archive bomb attacks across 9 formats — without decompressing any data. |

## Repository layout

Each subdirectory is a standalone project; there is no shared build. Enter one and follow its README:

```bash
cd Acoustic-Keylogger
cat README.md
```

## License

MIT — see the `LICENSE` file in each project.
