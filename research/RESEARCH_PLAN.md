# Research Plan

## Working Title

**Design and Evaluation of Post-Quantum Secure Communication Using ML-KEM**

## Objective

Build an experimental secure-channel platform and quantify the engineering impact of replacing or augmenting classical key establishment with ML-KEM.

## Baseline Measurements

- Handshake latency
- Public-key and ciphertext overhead
- End-to-end session setup time
- CPU usage
- Memory usage
- Encrypted-message overhead

## Comparative Evaluation

Later versions will compare:

- A classical key-establishment baseline
- ML-KEM key establishment
- Hybrid classical + ML-KEM key establishment
- Conventional and controlled privacy-preserving transport environments

## Threat Model

The research distinguishes between:

- Message confidentiality
- Peer authentication
- Message integrity
- Replay resistance
- Endpoint compromise
- Metadata exposure
- Transport anonymity

ML-KEM addresses post-quantum key establishment, not every property required by a complete secure communication protocol.
