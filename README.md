# MKEM Link

**Post-Quantum Secure Communication**

MKEM Link is a research-oriented secure communication prototype using **ML-KEM-768** for post-quantum key establishment and **AES-256-GCM** for authenticated encrypted messaging.

> **Research prototype:** This project has not been independently audited and is not intended for production security use.

## Architecture

```text
Client                                  Host
  |                                      |
  | <-------- ML-KEM public key -------- |
  |                                      |
  |  ML-KEM encapsulation                |
  |  -> shared secret                    |
  |                                      |
  | -------- KEM ciphertext -----------> |
  |                         decapsulation |
  |                         -> same secret|
  |                                      |
  |       HKDF-SHA-256 on both sides     |
  |                 |                    |
  |           AES-256 session key        |
  |                 |                    |
  | <==== AES-256-GCM messages ========> |
```

ML-KEM does **not** encrypt chat messages directly. It establishes shared keying material. HKDF-SHA-256 derives the session key, and AES-256-GCM provides authenticated message encryption.

## Features

- Clean desktop interface
- Host and client modes
- ML-KEM-768 key generation, encapsulation and decapsulation
- HKDF-SHA-256 session-key derivation
- AES-256-GCM authenticated encryption
- Length-prefixed TCP message framing
- Fresh random 96-bit GCM nonces
- Localhost and LAN research demonstrations

## Run

Requires Python 3.11+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

On Windows, activate with `.venv\Scripts\activate`.

For a local demonstration, run two instances. Choose **Host** in one instance and **Start Chat** in the other, connecting to `127.0.0.1` on port `8000`.

## Research Roadmap

1. Baseline ML-KEM-768 + AES-256-GCM secure channel
2. Endpoint identity authentication and handshake transcript binding
3. Replay/ordering protection and secure session lifecycle
4. Classical, ML-KEM and hybrid key-establishment modes
5. ML-KEM-512/768/1024 benchmarking
6. Latency, CPU, memory and bandwidth evaluation
7. Controlled privacy-preserving transport experiments
8. Formal threat-model and protocol analysis

## Research Questions

- What deployment overhead does ML-KEM introduce compared with classical key establishment?
- How does hybrid key establishment affect latency and bandwidth?
- How do higher-latency privacy-preserving transports affect post-quantum handshakes?
- Which protocol mechanisms are required around a KEM to construct a robust secure channel?

## License

MIT License. See [LICENSE](LICENSE).