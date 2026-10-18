require "sync/mutex"

module Crystal::Pqc::Constant
  # Low-level C ABI bindings to `libsodium` for guarded heap allocation,
  # page protection, deterministic memory zeroing, and constant-time comparison.
  @[Link("sodium")]
  lib LibSodium
    fun sodium_init : Int32
    fun sodium_malloc(size : LibC::SizeT) : Void*
    fun sodium_free(ptr : Void*) : Void
    fun sodium_mprotect_readonly(ptr : Void*) : Int32
    fun sodium_mprotect_readwrite(ptr : Void*) : Int32
    fun sodium_memzero(pnt : Void*, len : LibC::SizeT) : Void
    fun sodium_memcmp(b1 : UInt8*, b2 : UInt8*, len : LibC::SizeT) : Int32
  end

  # Thread-safe `libsodium` initialization, constant-time byte comparison,
  # and explicit buffer zeroing utilities.
  module Sodium
    @@init_mutex = Sync::Mutex.new
    @@initialized = Atomic(Bool).new(false)

    # Initializes `libsodium` idempotently across concurrent fibers and OS threads.
    def self.init : Nil
      return if @@initialized.get

      @@init_mutex.synchronize do
        return if @@initialized.get

        if LibSodium.sodium_init < 0
          raise PQCError.new("Failed to initialize libsodium")
        end

        @@initialized.set(true)
      end
    end

    # Compares two byte slices in constant time using `sodium_memcmp`.
    def self.constant_time_equal?(a : Bytes, b : Bytes) : Bool
      return true if a.empty? && b.empty?
      return false if a.size != b.size

      init
      LibSodium.sodium_memcmp(a.to_unsafe, b.to_unsafe, a.size) == 0
    end

    # Wipes the contents of *slice* in place using `sodium_memzero` so the
    # compiler cannot dead-store eliminate the zeroing operation.
    def self.memzero(slice : Bytes) : Nil
      return if slice.empty?

      init
      LibSodium.sodium_memzero(slice.to_unsafe.as(Void*), slice.size)
    end
  end

  # Guarded memory buffer allocated via `sodium_malloc`, protected with
  # `sodium_mprotect_readonly`, and synchronized under `Sync::Mutex`.
  class SecureBuffer
    # Size of the guarded allocation in bytes.
    getter size : Int32

    @ptr : Pointer(UInt8)
    @disposed : Bool = false
    @mutex : Sync::Mutex = Sync::Mutex.new

    # Allocates guarded memory for *bytes*, copies its contents in, and marks
    # the memory pages read-only.
    def initialize(bytes : Bytes) : Nil
      Sodium.init
      @size = bytes.size
      raise InvalidKeyError.new("SecureBuffer size must be positive") if @size <= 0

      void_ptr = LibSodium.sodium_malloc(@size.to_u64)
      raise PQCError.new("sodium_malloc failed to allocate #{@size} bytes") if void_ptr.null?

      @ptr = void_ptr.as(Pointer(UInt8))
      bytes.copy_to(Bytes.new(@ptr, @size))
      protect_readonly(void_ptr)
    end

    # Yields a read-only `Bytes` view of the guarded buffer while holding the
    # synchronization lock, raising `DisposedError` if already disposed.
    def with_slice(& : Bytes -> T) : T forall T
      @mutex.synchronize do
        raise DisposedError.new("SecureBuffer has already been disposed") if @disposed || @ptr.null?

        yield Bytes.new(@ptr, @size, read_only: true)
      end
    end

    # Returns `true` if the guarded memory has been wiped and freed.
    def disposed? : Bool
      @mutex.synchronize { @disposed }
    end

    # Marks the guarded memory read-write, zeroes its contents, and frees the
    # allocation via `sodium_free` idempotently.
    def dispose : Nil
      @mutex.synchronize do
        return if @disposed || @ptr.null?

        void_ptr = @ptr.as(Void*)
        LibSodium.sodium_mprotect_readwrite(void_ptr)
        LibSodium.sodium_memzero(void_ptr, @size.to_u64)
        LibSodium.sodium_free(void_ptr)
        @ptr = Pointer(UInt8).null
        @disposed = true
      end
    end

    # Ensures the guarded memory is wiped and freed if garbage-collected prior
    # to explicit disposal.
    def finalize : Nil
      dispose
    end

    private def protect_readonly(void_ptr : Void*) : Nil
      return if LibSodium.sodium_mprotect_readonly(void_ptr) == 0

      LibSodium.sodium_memzero(void_ptr, @size.to_u64)
      LibSodium.sodium_free(void_ptr)
      @ptr = Pointer(UInt8).null
      @disposed = true
      raise PQCError.new("sodium_mprotect_readonly failed")
    end
  end
end
