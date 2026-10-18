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
       version: ~> 0.1.0

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
     signature = signer.sign(message)
     valid = signer.verify(message, signature)
     puts "ML-DSA-65 signature valid: #{valid}"
   ensure
     signer.dispose
   end
