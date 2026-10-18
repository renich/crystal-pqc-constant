==========================
Return on Investment Goals
==========================

Strategic Objectives
--------------------

#. **Zero External Shard Dependencies**: The library must link directly against system ``libcrypto`` (OpenSSL 3.5+) and ``libsodium`` without introducing third-party Crystal shards, eliminating supply-chain drift.
#. **Complete NIST FIPS 203 and FIPS 204 Coverage**: The library must provide all six standardized parameter sets (``ML-KEM-512``, ``ML-KEM-768``, ``ML-KEM-1024``, ``ML-DSA-44``, ``ML-DSA-65``, and ``ML-DSA-87``) with FIPS 204 domain-separation context strings and deterministic seed derivation.
#. **Deterministic Secret Lifecycle**: The library must eliminate garbage-collector retention of private keys and shared secrets through explicit ``#dispose`` and single-use ``SharedSecret#consume`` lexical blocks.
#. **Drop-In Companion to Classical ECC**: The library must mirror the ``crystal-ecc-constant`` API ergonomics so hybrid classical/post-quantum protocols combine ``X25519`` with ``ML-KEM-768`` and ``Ed25519`` with ``ML-DSA-65`` without architectural friction.
