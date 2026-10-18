=================
Problem Statement
=================

Cryptographic Threat Landscape
------------------------------

Classical public-key cryptography based on elliptic curve discrete logarithms (``X25519``, ``Ed25519``, ``ECDSA``) and integer factorization (``RSA``) is vulnerable to Shor's algorithm on cryptographically relevant quantum computers. Harvest-Now-Decrypt-Later adversaries actively capture encrypted transport and identity payloads today for retroactive decryption once fault-tolerant quantum hardware reaches scale.

Simultaneously, conventional high-level language runtimes store secret keys and shared secrets inside garbage-collected heap memory. Garbage-collected heaps copy objects across generations, leave unzeroed key remnants in freed pages, and expose sensitive material to swap partitions and core dumps.

Architectural Solution
----------------------

``crystal-pqc-constant`` eliminates both failure modes through a deterministic two-layer architecture:

#. **Standardized NIST Post-Quantum Primitives**: Implements NIST FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism (``ML-KEM-512``, ``ML-KEM-768``, ``ML-KEM-1024``) and NIST FIPS 204 Module-Lattice-Based Digital Signature Algorithm (``ML-DSA-44``, ``ML-DSA-65``, ``ML-DSA-87``) backed by OpenSSL 3.5+ ``libcrypto`` ``EVP_PKEY`` providers.
#. **Guarded Memory Isolation**: Pins all long-lived secret keys and 32-byte shared secrets inside ``libsodium`` guarded heap allocations (``sodium_malloc``), locks page permissions to read-only at rest via ``sodium_mprotect_readonly``, and enforces deterministic zeroization via ``sodium_memzero`` prior to release.
