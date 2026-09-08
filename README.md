# MKEM Link

**Post-Quantum Secure Communication — Research Prototype**

MKEM Link explores the architecture of a post-quantum secure communication channel using **ML-KEM-768** for post-quantum key establishment, **HKDF-SHA-256** for session-key derivation, and **AES-256-GCM** for authenticated encrypted messaging.

## Browser experience

The repository now includes a responsive `index.html` experience designed for desktop, phone, and iPad. Publish the repository with GitHub Pages to get a public browser link.

> **Important:** The current browser experience is an interactive protocol demonstration. It visualizes the secure-channel flow and message UI, but it does not yet connect two real remote peers. It must not be represented as an audited or production-secure messenger.

## Architecture

```text
Peer A                              Peer B
  |                                  |
  | <----- ML-KEM material --------> |
  |                                  |
  |       shared keying material     |
  |                 |                |
  |          HKDF-SHA-256            |
  |                 |                |
  |        AES-256 session key       |
  |                 |                |
  | <=== AES-256-GCM messages ====>  |
```

ML-KEM does **not** encrypt chat messages directly. It establishes shared keying material. HKDF derives a session key, while AES-256-GCM provides authenticated message encryption.

## Research roadmap

1. Interactive browser protocol demo
2. Real networked peer transport
3. Endpoint identity authentication and transcript binding
4. Replay/ordering protection and secure session lifecycle
5. Classical, ML-KEM and hybrid key-establishment modes
6. ML-KEM-512/768/1024 benchmarking
7. Latency, CPU, memory and bandwidth evaluation
8. Controlled privacy-preserving transport experiments
9. Formal threat-model and protocol analysis

## Research questions

- What deployment overhead does ML-KEM introduce compared with classical key establishment?
- How does hybrid key establishment affect latency and bandwidth?
- How do higher-latency privacy-preserving transports affect post-quantum handshakes?
- Which mechanisms are required around a KEM to construct a robust authenticated secure channel?

## Security status

Research software. Not independently audited. Do not use the current prototype to protect sensitive or production communications.

## License

MIT License. See `LICENSE`.