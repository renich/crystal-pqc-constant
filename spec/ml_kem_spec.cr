require "./spec_helper"

describe Crystal::Pqc::Constant::MLKEMKeyPair do
  describe "KEMVariant metadata" do
    it "reports FIPS 203 byte sizes and algorithm names" do
      v512 = Crystal::Pqc::Constant::KEMVariant::MLKEM512
      v512.algorithm_name.should eq("ML-KEM-512")
      v512.public_key_size.should eq(800)
      v512.secret_key_size.should eq(1632)
      v512.ciphertext_size.should eq(768)
      v512.shared_secret_size.should eq(32)

      v768 = Crystal::Pqc::Constant::KEMVariant::MLKEM768
      v768.algorithm_name.should eq("ML-KEM-768")
      v768.public_key_size.should eq(1184)
      v768.secret_key_size.should eq(2400)
      v768.ciphertext_size.should eq(1088)
      v768.shared_secret_size.should eq(32)

      v1024 = Crystal::Pqc::Constant::KEMVariant::MLKEM1024
      v1024.algorithm_name.should eq("ML-KEM-1024")
      v1024.public_key_size.should eq(1568)
      v1024.secret_key_size.should eq(3168)
      v1024.ciphertext_size.should eq(1568)
      v1024.shared_secret_size.should eq(32)
    end
  end

  [
    Crystal::Pqc::Constant::KEMVariant::MLKEM512,
    Crystal::Pqc::Constant::KEMVariant::MLKEM768,
    Crystal::Pqc::Constant::KEMVariant::MLKEM1024,
  ].each do |variant|
    describe variant.algorithm_name do
      it "generates keys, roundtrips from_raw_keys, and encapsulates/decapsulates shared secrets" do
        kp = Crystal::Pqc::Constant::MLKEMKeyPair.generate(variant)
        begin
          kp.variant.should eq(variant)
          pub = kp.public_key
          sec = kp.secret_key
          pub.size.should eq(variant.public_key_size)
          sec.size.should eq(variant.secret_key_size)

          restored = Crystal::Pqc::Constant::MLKEMKeyPair.from_raw_keys(pub, sec, variant)
          begin
            enc = Crystal::Pqc::Constant::MLKEMKeyPair.encapsulate(restored.public_key, variant)
            enc[:ciphertext].size.should eq(variant.ciphertext_size)
            dec_secret = restored.decapsulate(enc[:ciphertext])

            agreed = enc[:shared_secret].consume do |first_secret|
              dec_secret.consume do |second_secret|
                Crystal::Pqc::Constant::Sodium.constant_time_equal?(first_secret, second_secret)
              end
            end
            agreed.should be_true
            enc[:shared_secret].disposed?.should be_true
            dec_secret.disposed?.should be_true
          ensure
            restored.dispose
            Crystal::Pqc::Constant::Sodium.memzero(sec)
          end
        ensure
          kp.dispose
        end
      end

      it "performs implicit rejection when a ciphertext byte is flipped" do
        kp = Crystal::Pqc::Constant::MLKEMKeyPair.generate(variant)
        begin
          enc = kp.encapsulate
          tampered = enc[:ciphertext].dup
          tampered[0] ^= 0xff_u8

          rejected_secret = kp.decapsulate(tampered)
          matches = enc[:shared_secret].consume do |original|
            rejected_secret.consume do |rejected|
              Crystal::Pqc::Constant::Sodium.constant_time_equal?(original, rejected)
            end
          end
          matches.should be_false
        ensure
          kp.dispose
        end
      end

      it "raises InvalidKeyError on invalid public key, secret key, or ciphertext sizes" do
        kp = Crystal::Pqc::Constant::MLKEMKeyPair.generate(variant)
        begin
          expect_raises(Crystal::Pqc::Constant::InvalidKeyError) do
            Crystal::Pqc::Constant::MLKEMKeyPair.from_raw_keys(Bytes.new(10), kp.secret_key, variant)
          end

          expect_raises(Crystal::Pqc::Constant::InvalidKeyError) do
            Crystal::Pqc::Constant::MLKEMKeyPair.from_raw_keys(kp.public_key, Bytes.new(10), variant)
          end

          expect_raises(Crystal::Pqc::Constant::InvalidKeyError) do
            Crystal::Pqc::Constant::MLKEMKeyPair.encapsulate(Bytes.new(10), variant)
          end

          expect_raises(Crystal::Pqc::Constant::InvalidKeyError) do
            kp.decapsulate(Bytes.new(variant.ciphertext_size - 1))
          end
        ensure
          kp.dispose
        end
      end

      it "raises InvalidKeyError when raw public key does not match secret key" do
        kp1 = Crystal::Pqc::Constant::MLKEMKeyPair.generate(variant)
        kp2 = Crystal::Pqc::Constant::MLKEMKeyPair.generate(variant)
        begin
          expect_raises(Crystal::Pqc::Constant::InvalidKeyError) do
            Crystal::Pqc::Constant::MLKEMKeyPair.from_raw_keys(kp1.public_key, kp2.secret_key, variant)
          end
        ensure
          kp1.dispose
          kp2.dispose
        end
      end

      it "raises DisposedError on operations after dispose" do
        kp = Crystal::Pqc::Constant::MLKEMKeyPair.generate(variant)
        enc = kp.encapsulate
        enc[:shared_secret].dispose
        kp.dispose
        kp.disposed?.should be_true

        expect_raises(Crystal::Pqc::Constant::DisposedError) { kp.public_key }
        expect_raises(Crystal::Pqc::Constant::DisposedError) { kp.secret_key }
        expect_raises(Crystal::Pqc::Constant::DisposedError) { kp.encapsulate }
        expect_raises(Crystal::Pqc::Constant::DisposedError) { kp.decapsulate(enc[:ciphertext]) }
      end
    end
  end

  it "supports concurrent encapsulate and decapsulate across fibers without data races" do
    kp = Crystal::Pqc::Constant::MLKEMKeyPair.generate
    begin
      channel = Channel(Bool).new(16)
      16.times do
        spawn do
          enc = kp.encapsulate
          dec = kp.decapsulate(enc[:ciphertext])
          ok = enc[:shared_secret].consume do |a|
            dec.consume do |b|
              Crystal::Pqc::Constant::Sodium.constant_time_equal?(a, b)
            end
          end
          channel.send(ok)
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
