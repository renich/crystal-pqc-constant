=================
Problem Statement
=================

Context
-------

Classical public-key cryptography based on elliptic curve discrete logarithms (``X25519``, ``Ed25519``, ``ECDSA``) and integer factorization (``RSA``) is vulnerable to Shor's algorithm on cryptographically relevant quantum computers. Harvest-Now-Decrypt-Later adversaries already capture encrypted traffic today for future decryption. Meanwhile, storing post-quantum secret keys on a garbage-collected heap exposes sensitive key material to memory copying, swap paging, and core dumps.

Solution
--------

``crystal-pqc-constant`` provides a standalone, zero-dependency Crystal shard implementing NIST FIPS 203 (``ML-KEM-512``, ``ML-KEM-768``, ``ML-KEM-1024``) and NIST FIPS 204 (``ML-DSA-44``, ``ML-DSA-65``, ``ML-DSA-87``) via OpenSSL 3.5+ ``EVP_PKEY`` providers while pinning all long-lived secret keys and shared secrets in ``libsodium`` guarded memory (``sodium_malloc`` + ``sodium_mprotect_readonly``).
