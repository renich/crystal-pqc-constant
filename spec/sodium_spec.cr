require "./spec_helper"

# Verifies [FUNC-003], [FUNC-004], [FUNC-005] / [TECH-001]
describe Crystal::Pqc::Constant do
  it "defines VERSION 0.1.1" do
    Crystal::Pqc::Constant::VERSION.should eq("0.1.1")
  end

  describe Crystal::Pqc::Constant::Sodium do
    it "initializes libsodium idempotently" do
      Crystal::Pqc::Constant::Sodium.init
      Crystal::Pqc::Constant::Sodium.init
    end

    it "compares byte slices in constant time" do
      a = Bytes[1, 2, 3, 4]
      b = Bytes[1, 2, 3, 4]
      c = Bytes[1, 2, 3, 5]
      d = Bytes[1, 2, 3]

      Crystal::Pqc::Constant::Sodium.constant_time_equal?(a, b).should be_true
      Crystal::Pqc::Constant::Sodium.constant_time_equal?(a, c).should be_false
      Crystal::Pqc::Constant::Sodium.constant_time_equal?(a, d).should be_false
      Crystal::Pqc::Constant::Sodium.constant_time_equal?(Bytes.empty, Bytes.empty).should be_true
    end

    it "zeroes mutable byte slices in place" do
      buf = Bytes[0xaa, 0xbb, 0xcc, 0xdd]
      Crystal::Pqc::Constant::Sodium.memzero(buf)
      buf.should eq(Bytes[0, 0, 0, 0])
    end
  end

  describe Crystal::Pqc::Constant::SecureBuffer do
    it "allocates guarded memory, yields a read-only slice, and disposes deterministically" do
      source = Bytes[10, 20, 30, 40, 50]
      buf = Crystal::Pqc::Constant::SecureBuffer.new(source)
      buf.size.should eq(5)
      buf.disposed?.should be_false

      copied = buf.with_slice(&.dup)
      copied.should eq(source)

      buf.dispose
      buf.disposed?.should be_true
      buf.dispose

      expect_raises(Crystal::Pqc::Constant::DisposedError) do
        buf.with_slice(&.size)
      end
    end

    it "rejects empty buffers with InvalidKeyError" do
      expect_raises(Crystal::Pqc::Constant::InvalidKeyError) do
        Crystal::Pqc::Constant::SecureBuffer.new(Bytes.empty)
      end
    end
  end

  describe Crystal::Pqc::Constant::SharedSecret do
    it "auto-disposes guarded memory after consume and raises DisposedError on reuse" do
      raw = Bytes.new(32, 0x5a_u8)
      secret = Crystal::Pqc::Constant::SharedSecret.new(raw)
      secret.disposed?.should be_false

      extracted = secret.consume(&.dup)
      extracted.should eq(raw)
      secret.disposed?.should be_true

      expect_raises(Crystal::Pqc::Constant::DisposedError) do
        secret.consume(&.size)
      end
    end

    it "rejects non-32-byte slices with InvalidKeyError" do
      expect_raises(Crystal::Pqc::Constant::InvalidKeyError) do
        Crystal::Pqc::Constant::SharedSecret.new(Bytes.new(16, 1_u8))
      end
    end
  end

  # Verifies [FUNC-006] / [TECH-006] and [FUNC-007] / [TECH-007]
  describe Crystal::Pqc::Constant::EvpKeyHelper do
    it "constructs a null-terminated 2-element OsslParamData array for octet strings" do
      payload = Bytes[0x10, 0x20, 0x30]
      params = Crystal::Pqc::Constant::EvpKeyHelper.build_octet_param_array("context-string", payload)
      params.size.should eq(2)
      params[0].data_type.should eq(Crystal::Pqc::Constant::LibCryptoPQC::OSSL_PARAM_OCTET_STRING)
      params[0].data_size.should eq(LibC::SizeT.new(3))
      params[1].key.null?.should be_true
      params[1].data_type.should eq(0_u32)
    end
  end
end
