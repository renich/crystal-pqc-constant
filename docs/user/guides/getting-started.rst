===============
Getting Started
===============

System Prerequisites
--------------------

Ensure Crystal (``>= 1.21.0``), OpenSSL 3.5+ development headers, and ``libsodium`` development headers are installed:

* **Fedora Linux**: ``sudo dnf install crystal openssl-devel libsodium-devel``
* **Alpine Linux**: ``apk add crystal openssl-dev libsodium-dev``

Installation
------------

Add ``crystal-pqc-constant`` to your ``shard.yml``:

.. code-block:: yaml

   dependencies:
     crystal-pqc-constant:
       gitlab: renich/crystal-pqc-constant
       version: ~> 0.1.1

ML-KEM Key Encapsulation Example
--------------------------------

.. code-block:: crystal

   require "crystal-pqc-constant"

   alice = Crystal::Pqc::Constant::MLKEMKeyPair.generate(
     Crystal::Pqc::Constant::KEMVariant::MLKEM768
   )
   begin
     enc = Crystal::Pqc::Constant::MLKEMKeyPair.encapsulate(alice.public_key)
     dec_secret = alice.decapsulate(enc[:ciphertext])

     agreed = enc[:shared_secret].consume do |bob_ss|
       dec_secret.consume do |alice_ss|
         Crystal::Pqc::Constant::Sodium.constant_time_equal?(bob_ss, alice_ss)
       end
     end
     puts "ML-KEM-768 shared secret agreed: #{agreed}"
   ensure
     alice.dispose
   end

ML-DSA Digital Signature Example
--------------------------------

.. code-block:: crystal

   require "crystal-pqc-constant"

   signer = Crystal::Pqc::Constant::MLDSAKeyPair.generate(
     Crystal::Pqc::Constant::DSAVariant::MLDSA65
   )
   begin
     message = "Authenticated post-quantum payload".to_slice
     context = "evalinux-fido2-v1".to_slice
     signature = signer.sign(message, context: context)
     valid = signer.verify(message, signature, context: context)
     puts "ML-DSA-65 signature valid: #{valid}"
   ensure
     signer.dispose
   end

Deterministic Seed Key Generation
---------------------------------

.. code-block:: crystal

   require "crystal-pqc-constant"

   kem_seed = Bytes.new(64) { |i| i.to_u8 }
   dsa_seed = Bytes.new(32) { |i| i.to_u8 }

   kem_pair = Crystal::Pqc::Constant::MLKEMKeyPair.from_seed(kem_seed)
   dsa_pair = Crystal::Pqc::Constant::MLDSAKeyPair.from_seed(dsa_seed)
   begin
     puts "Deterministic ML-KEM-768 public key bytes: #{kem_pair.public_key.size}"
     puts "Deterministic ML-DSA-65 public key bytes: #{dsa_pair.public_key.size}"
   ensure
     kem_pair.dispose
     dsa_pair.dispose
   end
