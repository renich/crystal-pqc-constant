require "./spec_helper"

# Verifies [FUNC-002], [FUNC-003], [FUNC-004], [FUNC-005], [FUNC-006], [FUNC-007]
# Verifies [TECH-002], [TECH-003], [TECH-005], [TECH-006], [TECH-007]
describe Crystal::Pqc::Constant::MLDSAKeyPair do
  describe "DSAVariant metadata" do
    it "reports FIPS 204 byte sizes and algorithm names" do
      v44 = Crystal::Pqc::Constant::DSAVariant::MLDSA44
      v44.algorithm_name.should eq("ML-DSA-44")
      v44.public_key_size.should eq(1312)
      v44.secret_key_size.should eq(2560)
      v44.signature_size.should eq(2420)

      v65 = Crystal::Pqc::Constant::DSAVariant::MLDSA65
      v65.algorithm_name.should eq("ML-DSA-65")
      v65.public_key_size.should eq(1952)
      v65.secret_key_size.should eq(4032)
      v65.signature_size.should eq(3309)

      v87 = Crystal::Pqc::Constant::DSAVariant::MLDSA87
      v87.algorithm_name.should eq("ML-DSA-87")
      v87.public_key_size.should eq(2592)
      v87.secret_key_size.should eq(4896)
      v87.signature_size.should eq(4627)
    end
  end

  [
    Crystal::Pqc::Constant::DSAVariant::MLDSA44,
    Crystal::Pqc::Constant::DSAVariant::MLDSA65,
    Crystal::Pqc::Constant::DSAVariant::MLDSA87,
  ].each do |variant|
    describe variant.algorithm_name do
      it "generates keys, roundtrips from_raw_keys, and signs and verifies messages" do
        kp = Crystal::Pqc::Constant::MLDSAKeyPair.generate(variant)
        begin
          kp.variant.should eq(variant)
          pub = kp.public_key
          sec = kp.secret_key
          pub.size.should eq(variant.public_key_size)
          sec.size.should eq(variant.secret_key_size)

          restored = Crystal::Pqc::Constant::MLDSAKeyPair.from_raw_keys(pub, sec, variant)
          begin
            msg = "Post-Quantum FIDO2 / WebAuthn assertion payload".to_slice
            sig = restored.sign(msg)
            sig.size.should eq(variant.signature_size)

            restored.verify(msg, sig).should be_true
            Crystal::Pqc::Constant::MLDSAKeyPair.verify(pub, msg, sig, variant).should be_true
          ensure
            restored.dispose
            Crystal::Pqc::Constant::Sodium.memzero(sec)
          end
        ensure
          kp.dispose
        end
      end

      it "rejects tampered messages, tampered signatures, wrong signature sizes, and cross-key verification" do
        kp1 = Crystal::Pqc::Constant::MLDSAKeyPair.generate(variant)
        kp2 = Crystal::Pqc::Constant::MLDSAKeyPair.generate(variant)
        begin
          msg = "Canonical signed message".to_slice
          sig = kp1.sign(msg)

          tampered_msg = "Canonical signed messagf".to_slice
          kp1.verify(tampered_msg, sig).should be_false

          tampered_sig = sig.dup
          tampered_sig[0] ^= 0x01_u8
          kp1.verify(msg, tampered_sig).should be_false

          kp1.verify(msg, Bytes.new(16)).should be_false
          kp2.verify(msg, sig).should be_false
        ensure
          kp1.dispose
          kp2.dispose
        end
      end

      it "raises InvalidKeyError on invalid raw key sizes or mismatched key pairs" do
        kp1 = Crystal::Pqc::Constant::MLDSAKeyPair.generate(variant)
        kp2 = Crystal::Pqc::Constant::MLDSAKeyPair.generate(variant)
        begin
          expect_raises(Crystal::Pqc::Constant::InvalidKeyError) do
            Crystal::Pqc::Constant::MLDSAKeyPair.from_raw_keys(Bytes.new(12), kp1.secret_key, variant)
          end

          expect_raises(Crystal::Pqc::Constant::InvalidKeyError) do
            Crystal::Pqc::Constant::MLDSAKeyPair.from_raw_keys(kp1.public_key, Bytes.new(12), variant)
          end

          expect_raises(Crystal::Pqc::Constant::InvalidKeyError) do
            Crystal::Pqc::Constant::MLDSAKeyPair.from_raw_keys(kp1.public_key, kp2.secret_key, variant)
          end

          expect_raises(Crystal::Pqc::Constant::InvalidKeyError) do
            dummy_sig = Bytes.new(variant.signature_size)
            Crystal::Pqc::Constant::MLDSAKeyPair.verify(Bytes.new(12), "msg".to_slice, dummy_sig, variant)
          end
        ensure
          kp1.dispose
          kp2.dispose
        end
      end

      it "raises DisposedError on operations after dispose" do
        kp = Crystal::Pqc::Constant::MLDSAKeyPair.generate(variant)
        msg = "test".to_slice
        sig = kp.sign(msg)
        kp.dispose
        kp.disposed?.should be_true

        expect_raises(Crystal::Pqc::Constant::DisposedError) { kp.public_key }
        expect_raises(Crystal::Pqc::Constant::DisposedError) { kp.secret_key }
        expect_raises(Crystal::Pqc::Constant::DisposedError) { kp.sign(msg) }
        expect_raises(Crystal::Pqc::Constant::DisposedError) { kp.verify(msg, sig) }
      end

      # Verifies [FUNC-006] / [TECH-005], [TECH-006]
      it "enforces FIPS 204 domain-separation context strings (0..255 bytes)" do
        kp = Crystal::Pqc::Constant::MLDSAKeyPair.generate(variant)
        begin
          msg = "Domain-separated assertion".to_slice
          ctx1 = "fido2-webauthn-v1".to_slice
          ctx2 = "fido2-webauthn-v2".to_slice
          max_ctx = Bytes.new(255, 0x42_u8)

          sig_ctx1 = kp.sign(msg, context: ctx1)
          kp.verify(msg, sig_ctx1, context: ctx1).should be_true
          Crystal::Pqc::Constant::MLDSAKeyPair.verify(
            kp.public_key, msg, sig_ctx1, variant, context: ctx1
          ).should be_true

          kp.verify(msg, sig_ctx1).should be_false
          kp.verify(msg, sig_ctx1, context: ctx2).should be_false

          sig_max = kp.sign(msg, context: max_ctx)
          kp.verify(msg, sig_max, context: max_ctx).should be_true

          oversized_ctx = Bytes.new(256, 0x01_u8)
          expect_raises(Crystal::Pqc::Constant::SignatureError) do
            kp.sign(msg, context: oversized_ctx)
          end
          expect_raises(Crystal::Pqc::Constant::SignatureError) do
            kp.verify(msg, sig_ctx1, context: oversized_ctx)
          end
          expect_raises(Crystal::Pqc::Constant::SignatureError) do
            Crystal::Pqc::Constant::MLDSAKeyPair.verify(
              kp.public_key, msg, sig_ctx1, variant, context: oversized_ctx
            )
          end
        ensure
          kp.dispose
        end
      end

      # Verifies [FUNC-007] / [TECH-005], [TECH-007]
      it "derives deterministic keypairs from a 32-byte xi seed and rejects invalid seed lengths" do
        seed = Bytes.new(32) { |idx| (idx &* 11 &+ 5).to_u8! }
        kp1 = Crystal::Pqc::Constant::MLDSAKeyPair.from_seed(seed, variant)
        kp2 = Crystal::Pqc::Constant::MLDSAKeyPair.from_seed(seed, variant)
        begin
          kp1.public_key.should eq(kp2.public_key)
          sec1 = kp1.secret_key
          sec2 = kp2.secret_key
          begin
            sec1.should eq(sec2)
          ensure
            Crystal::Pqc::Constant::Sodium.memzero(sec1)
            Crystal::Pqc::Constant::Sodium.memzero(sec2)
          end

          expect_raises(Crystal::Pqc::Constant::InvalidKeyError) do
            Crystal::Pqc::Constant::MLDSAKeyPair.from_seed(Bytes.new(31), variant)
          end
          expect_raises(Crystal::Pqc::Constant::InvalidKeyError) do
            Crystal::Pqc::Constant::MLDSAKeyPair.from_seed(Bytes.new(33), variant)
          end
        ensure
          kp1.dispose
          kp2.dispose
        end
      end
    end
  end

  it "supports concurrent signing and verification across fibers without data races" do
    kp = Crystal::Pqc::Constant::MLDSAKeyPair.generate
    begin
      channel = Channel(Bool).new(16)
      16.times do |i|
        spawn do
          msg = "concurrent-message-#{i}".to_slice
          sig = kp.sign(msg)
          channel.send(kp.verify(msg, sig))
        end
      end

      16.times do
        channel.receive.should be_true
      end
    ensure
      kp.dispose
    end
  end
end
