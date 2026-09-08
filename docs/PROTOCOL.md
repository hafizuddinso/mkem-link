# MKEM Link Protocol — v0.1

## Handshake

1. The host generates an ephemeral ML-KEM-768 encapsulation/decapsulation key pair.
2. The host sends the ML-KEM encapsulation key to the client.
3. The client encapsulates against that key, producing a KEM ciphertext and shared secret.
4. The client sends the KEM ciphertext to the host.
5. The host decapsulates it and obtains the same shared secret.
6. Both endpoints derive a 32-byte session key using HKDF-SHA-256 with protocol context `MKEM-Link-v0.1`.

## Message Encryption

Messages are protected using AES-256-GCM. Each message uses a fresh random 12-byte nonce and protocol-associated data `MKEM-Link`.

## Scope

ML-KEM provides post-quantum key establishment. AES-256-GCM provides confidentiality and authentication for application messages.

## Current Limitations

This research prototype does not yet provide:

- Endpoint identity authentication
- Handshake transcript binding
- Persistent cryptographic identities
- Production-grade replay and ordering protection
- Formal forward-secrecy guarantees

These limitations are part of the project's research roadmap rather than claims of completed security properties.
