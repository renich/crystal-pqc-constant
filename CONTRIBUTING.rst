====================================
Contributing to crystal-pqc-constant
====================================

Thank you for your interest in contributing to ``crystal-pqc-constant``. We welcome contributions from human engineers and autonomous agents who share our commitment to cryptographic rigor, memory safety, and empirical verification.

Code of Honor
=============

All contributors are expected to uphold the principles defined in `CODE_OF_HONOR.rst <CODE_OF_HONOR.rst>`__. We build resilient, well-tested software, demand intellectual honesty, operate transparently, and verify all library behaviors empirically.

Development Workflow
====================

Prerequisites
-------------

* `Crystal <https://crystal-lang.org/>`__ (>= 1.21.0)
* `OpenSSL <https://www.openssl.org/>`__ (>= 3.5.0 with ML-KEM and ML-DSA providers)
* `libsodium <https://doc.libsodium.org/>`__
* `GNU Make <https://www.gnu.org/software/make/>`__
* `cRSTLint <https://gitlab.com/renich/crstlint>`__ and ``rstcheck``

Setting Up the Workspace
------------------------

#. Clone the repository:

   .. code-block:: bash

      git clone git@gitlab.com:renich/crystal-pqc-constant.git
      cd crystal-pqc-constant

#. Install development dependencies and run verification gates:

   .. code-block:: bash

      shards install
      make all
      make doc-check

Testing and Quality Standards
=============================

We adhere strictly to Test-Driven Development and the principle of **Do Not Assume; Always Verify**.

Running Checks
--------------

* **Run test suite**:

   .. code-block:: bash

      make test

* **Run static linters**:

   .. code-block:: bash

      make lint

* **Validate RST Documentation**:

   .. code-block:: bash

      make doc-check

Git Commit Standards
====================

We enforce the Conventional Commits specification:

* ``feat(kem): add ML-KEM-768 encapsulation and decapsulation``
* ``feat(dsa): add ML-DSA-65 detached signing and verification``
* ``docs(adrs): document OpenSSL 3.5 and libsodium guarded memory architecture``
* ``test(spec): add concurrent fiber stress tests``

All commits must be signed and authored with full technical ownership.
