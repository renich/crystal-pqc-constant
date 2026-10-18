==========================
Return on Investment Goals
==========================

Strategic Objectives
--------------------

#. **Zero External Shard Dependencies**: Link directly against system ``libcrypto`` (OpenSSL 3.5+) and ``libsodium`` without pulling third-party Crystal shards.
#. **NIST Post-Quantum Compliance**: Support all standardized FIPS 203 ``ML-KEM`` and FIPS 204 ``ML-DSA`` parameter sets out of the box.
#. **Deterministic Secret Lifecycle**: Eliminate GC-resident private keys and shared secrets via explicit ``#dispose`` and ``SharedSecret#consume`` patterns.
#. **Drop-In Companion to Classical ECC**: Mirror the ``crystal-ecc-constant`` API ergonomics so hybrid classical/post-quantum protocols can combine ``X25519`` + ``ML-KEM-768`` and ``Ed25519`` + ``ML-DSA-65``.
