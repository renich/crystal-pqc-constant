=================
Core Requirements
=================

Traceability Matrix
-------------------

.. list-table::
   :widths: 15 40 30 15
   :header-rows: 1

   * - Requirement ID
     - Capability Summary
     - Technical Specs
     - Target Release
   * - ``[FUNC-001]``
     - NIST FIPS 203 ``ML-KEM`` Key Encapsulation
     - ``[TECH-002]``, ``[TECH-003]`` (:doc:`../../technical/specs/architecture-overview`), ``[TECH-005]`` (:doc:`../../technical/specs/threat-model`)
     - ``v0.1.0``
   * - ``[FUNC-002]``
     - NIST FIPS 204 ``ML-DSA`` Digital Signatures
     - ``[TECH-002]``, ``[TECH-003]`` (:doc:`../../technical/specs/architecture-overview`), ``[TECH-005]`` (:doc:`../../technical/specs/threat-model`)
     - ``v0.1.0``
   * - ``[FUNC-003]``
     - Guarded Memory Secret Isolation
     - ``[TECH-001]``, ``[TECH-003]`` (:doc:`../../technical/specs/architecture-overview`), ``[TECH-005]`` (:doc:`../../technical/specs/threat-model`)
     - ``v0.1.0``
   * - ``[FUNC-004]``
     - Raw Key Serialization and Keypair Consistency Validation
     - ``[TECH-002]``, ``[TECH-003]`` (:doc:`../../technical/specs/architecture-overview`), ``[TECH-004]`` (:doc:`../../technical/specs/coding-standards`)
     - ``v0.1.0``
   * - ``[FUNC-005]``
     - Thread-Safe Concurrent Execution
     - ``[TECH-001]`` (:doc:`../../technical/specs/architecture-overview`), ``[TECH-004]`` (:doc:`../../technical/specs/coding-standards`), :doc:`../../technical/specs/release-procedure`
     - ``v0.1.0``
   * - ``[FUNC-006]``
     - NIST FIPS 204 Domain-Separation Context String
     - ``[TECH-005]`` (:doc:`../../technical/specs/threat-model`), ``[TECH-006]`` (:doc:`../../technical/specs/architecture-overview`)
     - ``v0.1.1``
   * - ``[FUNC-007]``
     - Deterministic Seed Key Generation and NIST ACVP KAT Verification
     - ``[TECH-005]`` (:doc:`../../technical/specs/threat-model`), ``[TECH-007]`` (:doc:`../../technical/specs/architecture-overview`)
     - ``v0.1.1``

Functional Requirements
-----------------------

[FUNC-001] NIST FIPS 203 ML-KEM Key Encapsulation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The library must implement NIST FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism through ``Crystal::Pqc::Constant::KEMVariant`` and ``Crystal::Pqc::Constant::MLKEMKeyPair`` across all three standardized parameter sets (fulfilled by ``[TECH-002]`` and ``[TECH-003]`` in :doc:`../../technical/specs/architecture-overview` and ``[TECH-005]`` in :doc:`../../technical/specs/threat-model`):

.. list-table::
   :widths: 25 20 15 15 15 10
   :header-rows: 1

   * - Enum Member
     - OpenSSL Algorithm
     - Public Key Bytes
     - Secret Key Bytes
     - Ciphertext Bytes
     - Shared Secret Bytes
   * - ``KEMVariant::MLKEM512``
     - ``ML-KEM-512``
     - 800
     - 1632
     - 768
     - 32
   * - ``KEMVariant::MLKEM768``
     - ``ML-KEM-768``
     - 1184
     - 2400
     - 1088
     - 32
   * - ``KEMVariant::MLKEM1024``
     - ``ML-KEM-1024``
     - 1568
     - 3168
     - 1568
     - 32

* ``MLKEMKeyPair.generate`` must default to ``KEMVariant::MLKEM768`` and generate a fresh encapsulation/decapsulation key pair backed by OpenSSL 3.5+.
* ``MLKEMKeyPair.encapsulate`` and ``MLKEMKeyPair#encapsulate`` must return ``NamedTuple(ciphertext: Bytes, shared_secret: SharedSecret)`` and raise ``InvalidKeyError`` if the public key byte length does not match ``variant.public_key_size``.
* ``MLKEMKeyPair#decapsulate`` must enforce ``ciphertext.size == variant.ciphertext_size`` by raising ``InvalidKeyError`` on length mismatch, and must preserve FIPS 203 implicit rejection when decapsulating modified ciphertexts of valid length by returning a deterministic pseudorandom 32-byte ``SharedSecret`` without raising an exception or leaking timing differences.

[FUNC-002] NIST FIPS 204 ML-DSA Digital Signatures
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The library must implement NIST FIPS 204 Module-Lattice-Based Digital Signature Algorithm through ``Crystal::Pqc::Constant::DSAVariant`` and ``Crystal::Pqc::Constant::MLDSAKeyPair`` across all three standardized parameter sets (fulfilled by ``[TECH-002]`` and ``[TECH-003]`` in :doc:`../../technical/specs/architecture-overview` and ``[TECH-005]`` in :doc:`../../technical/specs/threat-model`):

.. list-table::
   :widths: 25 25 15 15 20
   :header-rows: 1

   * - Enum Member
     - OpenSSL Algorithm
     - Public Key Bytes
     - Secret Key Bytes
     - Signature Bytes
   * - ``DSAVariant::MLDSA44``
     - ``ML-DSA-44``
     - 1312
     - 2560
     - 2420
   * - ``DSAVariant::MLDSA65``
     - ``ML-DSA-65``
     - 1952
     - 4032
     - 3309
   * - ``DSAVariant::MLDSA87``
     - ``ML-DSA-87``
     - 2592
     - 4896
     - 4627

* ``MLDSAKeyPair.generate`` must default to ``DSAVariant::MLDSA65`` and generate a fresh signing/verification key pair backed by OpenSSL 3.5+.
* ``MLDSAKeyPair#sign`` must compute a detached signature of exact length ``variant.signature_size`` over arbitrary-length message slices including empty ``Bytes.empty`` payloads.
* ``MLDSAKeyPair#verify`` and ``MLDSAKeyPair.verify`` must raise ``InvalidKeyError`` if the public key length does not equal ``variant.public_key_size``, and must return ``false`` without raising an exception if the signature length is invalid or cryptographic verification fails over a modified message, modified signature, or wrong public key.

[FUNC-003] Guarded Memory Secret Isolation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The library must isolate all long-lived secret keys and 32-byte shared secrets inside ``libsodium`` guarded memory via ``Crystal::Pqc::Constant::SecureBuffer`` and ``Crystal::Pqc::Constant::SharedSecret`` (fulfilled by ``[TECH-001]`` and ``[TECH-003]`` in :doc:`../../technical/specs/architecture-overview` and ``[TECH-005]`` in :doc:`../../technical/specs/threat-model`):

* ``SecureBuffer.new`` must reject empty or non-positive slices with ``InvalidKeyError``, allocate guarded heap pages via ``sodium_malloc``, copy secret bytes into the guarded region, and lock page permissions to read-only via ``sodium_mprotect_readonly``.
* ``SecureBuffer#with_slice`` must yield a read-only ``Bytes`` view while holding an internal synchronization lock and raise ``DisposedError`` if the buffer has already been disposed.
* ``SecureBuffer#dispose`` must restore read-write permissions via ``sodium_mprotect_readwrite``, wipe the memory region via ``sodium_memzero``, release the page via ``sodium_free``, and remain idempotent across repeated invocations.
* ``SharedSecret#consume`` must copy the 32-byte secret into a temporary buffer, yield it to the caller block, and deterministically zero the temporary buffer via ``Sodium.memzero`` and dispose the underlying ``SecureBuffer`` inside an ``ensure`` block even if the caller block raises an exception.

[FUNC-004] Raw Key Serialization and Keypair Consistency Validation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The library must support deterministic raw key import and export with cryptographic consistency verification (fulfilled by ``[TECH-002]`` and ``[TECH-003]`` in :doc:`../../technical/specs/architecture-overview` and ``[TECH-004]`` in :doc:`../../technical/specs/coding-standards`):

* ``MLKEMKeyPair#public_key`` and ``MLDSAKeyPair#public_key`` must return defensive copies of the public key slice so caller mutation cannot corrupt internal state, and must raise ``DisposedError`` after ``#dispose``.
* ``MLKEMKeyPair#secret_key`` and ``MLDSAKeyPair#secret_key`` must return a freshly allocated copy of the guarded secret key bytes and raise ``DisposedError`` after ``#dispose``.
* ``MLKEMKeyPair.from_raw_keys`` and ``MLDSAKeyPair.from_raw_keys`` must validate that ``public_key.size`` and ``secret_key.size`` match the target variant, load the private key into OpenSSL 3.5+ ``EVP_PKEY``, extract the derived ``"pub"`` octet string parameter, and compare it against ``public_key`` using ``Sodium.constant_time_equal?``. Any size mismatch, malformed key material, or public/secret key mismatch must raise ``InvalidKeyError``.
* All domain failures must inherit from ``Crystal::Pqc::Constant::PQCError`` through the typed subclasses ``DisposedError``, ``InvalidKeyError``, ``EncapsulationError``, and ``SignatureError``.

[FUNC-005] Thread-Safe Concurrent Execution
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The library must guarantee memory safety and race-free operation across Crystal 1.21+ parallel execution contexts (fulfilled by ``[TECH-001]`` in :doc:`../../technical/specs/architecture-overview`, ``[TECH-004]`` in :doc:`../../technical/specs/coding-standards`, and :doc:`../../technical/specs/release-procedure`):

* ``Sodium.init`` must execute ``sodium_init`` idempotently under ``Sync::Mutex`` and ``Atomic(Bool)`` double-checked locking.
* ``SecureBuffer`` must serialize all ``#with_slice``, ``#dispose``, and ``#disposed?`` operations using ``Sync::Mutex`` so concurrent fibers sharing an ``MLKEMKeyPair``, ``MLDSAKeyPair``, or ``SharedSecret`` cannot trigger use-after-free or double-free faults.

[FUNC-006] NIST FIPS 204 Domain-Separation Context String
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For Phase 2 release ``v0.1.1``, ``MLDSAKeyPair#sign``, ``MLDSAKeyPair#verify``, and ``MLDSAKeyPair.verify`` must accept an optional keyword argument ``context : Bytes = Bytes.empty`` implementing NIST FIPS 204 Section 5.2 domain separation (fulfilled by ``[TECH-006]`` in :doc:`../../technical/specs/architecture-overview` and ``[TECH-005]`` in :doc:`../../technical/specs/threat-model`):

* The ``context`` slice must have a length in the inclusive range ``0..255`` bytes. Any ``context`` slice with ``context.size > 255`` must raise ``SignatureError`` prior to invoking OpenSSL.
* When ``context`` is non-empty, ``MLDSAKeyPair`` must pass the slice to OpenSSL 3.5+ ``EVP_DigestSignInit_ex`` and ``EVP_DigestVerifyInit_ex`` via an ``OSSL_PARAM`` array containing ``OSSL_SIGNATURE_PARAM_CONTEXT_STRING`` (``"context-string"``).
* A signature produced with context ``C1`` must verify as ``true`` only when verified with the identical context ``C1``, and must return ``false`` when verified with an empty context or any distinct context ``C2 != C1``.

[FUNC-007] Deterministic Seed Key Generation and NIST ACVP KAT Verification
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For Phase 2 release ``v0.1.1``, the library must provide deterministic seed-based key generation and automated NIST ACVP Known-Answer Test verification across all six parameter sets (fulfilled by ``[TECH-007]`` in :doc:`../../technical/specs/architecture-overview` and ``[TECH-005]`` in :doc:`../../technical/specs/threat-model`):

* ``MLKEMKeyPair.from_seed(seed : Bytes, variant : KEMVariant = KEMVariant::MLKEM768)`` must accept a 64-byte concatenation of the 32-byte ``d`` and 32-byte ``z`` FIPS 203 seeds, raise ``InvalidKeyError`` if ``seed.size != 64``, initialize an OpenSSL 3.5+ key generation context via ``EVP_PKEY_keygen_init``, inject the seed via ``EVP_PKEY_CTX_set_params`` with ``OSSL_PKEY_PARAM_ML_KEM_SEED`` (``"seed"``), execute ``EVP_PKEY_keygen``, and wipe temporary seed buffers via ``Sodium.memzero`` in ``ensure``.
* ``MLDSAKeyPair.from_seed(seed : Bytes, variant : DSAVariant = DSAVariant::MLDSA65)`` must accept a 32-byte FIPS 204 ``xi`` seed, raise ``InvalidKeyError`` if ``seed.size != 32``, initialize an OpenSSL 3.5+ key generation context via ``EVP_PKEY_keygen_init``, inject the seed via ``EVP_PKEY_CTX_set_params`` with ``OSSL_PKEY_PARAM_ML_DSA_SEED`` (``"seed"``), execute ``EVP_PKEY_keygen``, and wipe temporary seed buffers via ``Sodium.memzero`` in ``ensure``.
* The specification suite (``spec/acvp_kat_spec.cr``) must verify deterministic seed-derived keypair generation (``pub_sha256`` and ``sec_sha256`` Known-Answer Test digests) alongside hedged encapsulation/decapsulation and context-bound signature roundtrips across all six parameter sets (``ML-KEM-512``, ``ML-KEM-768``, ``ML-KEM-1024``, ``ML-DSA-44``, ``ML-DSA-65``, and ``ML-DSA-87``).
