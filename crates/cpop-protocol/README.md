# cpop_protocol

Core Rust implementation of the Proof-of-Process (CPoP) Protocol.

## Overview

Proof-of-Process (CPoP) is a protocol submitted as an IETF Independent Submission. It provides a mechanism for high-integrity process verification, ensuring that a particular process (human or automated) has occurred as claimed.

This crate serves as the core library for CPoP, providing the necessary cryptographic primitives, data structures, and protocol encoding (CBOR/COSE) required for interoperable implementations.

## Features

- **CBOR/COSE Encoding**: Native support for CPoP packet serialization following RFC 8949 and RFC 9052.
- **Cryptographic Primitives**: Integration with standard Rust crypto libraries for signatures and hashing.
- **Protocol Models**: Complete implementation of CPoP protocol models as defined in the internet-drafts.
- **Hardware Attestation**: Support for hardware-backed evidence collection and verification.
- **X.509 Identity**: Certificate-based identity with Proof-of-Possession verification.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
cpop-protocol = { git = "https://github.com/LF-Decentralized-Trust-labs/proof-of-process" }
```

## Related Projects

- [CPOP](https://github.com/LF-Decentralized-Trust-labs/proof-of-process): Monorepo containing all CPOP components.
- [cpop-jitter](../cpop-jitter): Hardware entropy collection primitive for CPoP.
- [draft-condrey-rats-pop](https://github.com/LF-Decentralized-Trust-labs/proof-of-process): IETF Internet-Draft source.

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](../../LICENSE) for details.
