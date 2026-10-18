require "./spec_helper"
require "digest/sha256"

# Verifies [FUNC-006], [FUNC-007] / [TECH-005], [TECH-007]
describe "NIST ACVP Deterministic Seed & Context KAT Suite" do
  describe "NIST FIPS 203 ML-KEM Known-Answer Vectors" do
    kem_vectors = {
      Crystal::Pqc::Constant::KEMVariant::MLKEM512 => {
        pub_sha256: "3ae268dccc5456ac0d0f9b39257dc48fe081383b97c400512d712b739762daee",
        sec_sha256: "17fb29b8c4baf74fb81eea15ffd583b3e37f5a5b8dcf6db96c72c3b3751d6f17",
      },
      Crystal::Pqc::Constant::KEMVariant::MLKEM768 => {
        pub_sha256: "0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9",
        sec_sha256: "dac268bde6a8dd238e9887117d6b664e7a7a9350ad6b7c08a948e504809572a5",
      },
      Crystal::Pqc::Constant::KEMVariant::MLKEM1024 => {
        pub_sha256: "c7b8fa0aa471d5ae18922d6ccad5b31e1d84f92ae723abfd13747018740a8530",
        sec_sha256: "3a2a676c5a242ee683cb6097c8f3e64fbef4d90267f9250ec2beab8f99621fad",
      },
    }

    kem_vectors.each do |variant, expected|
      it "reproduces deterministic #{variant.algorithm_name} KAT keys and encapsulates/decapsulates" do
        seed = Bytes.new(64, &.to_u8!)
        kp = Crystal::Pqc::Constant::MLKEMKeyPair.from_seed(seed, variant)
        begin
          pub = kp.public_key
          sec = kp.secret_key
          begin
            Digest::SHA256.hexdigest(pub).should eq(expected[:pub_sha256])
            Digest::SHA256.hexdigest(sec).should eq(expected[:sec_sha256])

            enc = kp.encapsulate
            dec = kp.decapsulate(enc[:ciphertext])
            agreed = enc[:shared_secret].consume do |first_ss|
              dec.consume do |second_ss|
                Crystal::Pqc::Constant::Sodium.constant_time_equal?(first_ss, second_ss)
              end
            end
            agreed.should be_true
          ensure
            Crystal::Pqc::Constant::Sodium.memzero(sec)
          end
        ensure
          kp.dispose
        end
      end
    end
  end

  describe "NIST FIPS 204 ML-DSA Known-Answer Vectors" do
    dsa_vectors = {
      Crystal::Pqc::Constant::DSAVariant::MLDSA44 => {
        pub_sha256: "9f107644c1084526af3bc8098680b05499a2325a644e388fb4f970e058d19d46",
        sec_sha256: "04bf6b9f579166a627961dfc5c3bf9717df868db88863856356c4668c8b56b0b",
      },
      Crystal::Pqc::Constant::DSAVariant::MLDSA65 => {
        pub_sha256: "d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9",
        sec_sha256: "9f1e24f47795fe50040384e3d6183988047170fa2d866406b70fe0a3f8216063",
      },
      Crystal::Pqc::Constant::DSAVariant::MLDSA87 => {
        pub_sha256: "91dc389cfaa01470b7f66eee45a4ae9026d154817c754dfe22298b3fa241ffcd",
        sec_sha256: "764d3e223ed90c07bc91a0ab6ecd170e5c66ffe39f7039298596039a36005435",
      },
    }

    dsa_vectors.each do |variant, expected|
      it "reproduces deterministic #{variant.algorithm_name} KAT keys and verifies context-bound signatures" do
        seed = Bytes.new(32, &.to_u8!)
        kp = Crystal::Pqc::Constant::MLDSAKeyPair.from_seed(seed, variant)
        begin
          pub = kp.public_key
          sec = kp.secret_key
          begin
            Digest::SHA256.hexdigest(pub).should eq(expected[:pub_sha256])
            Digest::SHA256.hexdigest(sec).should eq(expected[:sec_sha256])

            msg = "NIST ACVP FIPS 204 KAT message payload".to_slice
            ctx = "acvp-fips-204-context".to_slice
            other_ctx = "acvp-fips-204-other".to_slice

            sig = kp.sign(msg, context: ctx)
            kp.verify(msg, sig, context: ctx).should be_true
            kp.verify(msg, sig).should be_false
            kp.verify(msg, sig, context: other_ctx).should be_false
          ensure
            Crystal::Pqc::Constant::Sodium.memzero(sec)
          end
        ensure
          kp.dispose
        end
      end
    end
  end
end
