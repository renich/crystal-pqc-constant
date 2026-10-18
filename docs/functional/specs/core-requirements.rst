=================
Core Requirements
=================

Functional Requirements
-----------------------

* **[FUNC-001] NIST FIPS 203 ML-KEM Key Encapsulation**:
  Support key generation, raw key import/validation, encapsulation, and decapsulation across ``ML-KEM-512``, ``ML-KEM-768``, and ``ML-KEM-1024`` with implicit rejection on tampered ciphertexts.

* **[FUNC-002] NIST FIPS 204 ML-DSA Digital Signatures**:
  Support key generation, raw key import/validation, detached message signing, and signature verification across ``ML-DSA-44``, ``ML-DSA-65``, and ``ML-DSA-87``.

* **[FUNC-003] Guarded Secret Memory Lifecycle**:
  Pin secret keys and 32-byte shared secrets inside ``libsodium`` guarded allocations (``sodium_malloc``) protected by ``sodium_mprotect_readonly`` and deterministically wiped via ``sodium_memzero`` and ``sodium_free`` upon ``#dispose`` or ``SharedSecret#consume``.

* **[FUNC-004] Typed Domain Exception Hierarchy**:
  Provide ``PQCError``, ``DisposedError``, ``InvalidKeyError``, ``EncapsulationError``, and ``SignatureError`` for unambiguous failure handling.

* **[FUNC-005] Concurrency Safety**:
  Synchronize guarded buffer access and disposal via ``Sync::Mutex`` so concurrent Crystal fibers cannot trigger use-after-free or double-free conditions.
