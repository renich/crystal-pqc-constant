==================================
crystal-pqc-constant Documentation
==================================

**Post-Quantum Cryptography for Crystal Backed by OpenSSL 3.5+ and Guarded Memory.**

Welcome to the official documentation portal for ``crystal-pqc-constant``. This shard delivers NIST FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism (``ML-KEM``) and NIST FIPS 204 Module-Lattice-Based Digital Signature Algorithm (``ML-DSA``) with secret keys isolated inside ``libsodium`` guarded heap allocations.

Documentation Architecture
--------------------------

.. list-table::
   :widths: 25 45 30
   :header-rows: 1

   * - Guide
     - Purpose & Scope
     - Entrypoint
   * - **Business & Strategy**
     - Post-quantum migration vision, ecosystem goals, and user personas.
     - `Business Specifications <business/spec.rst>`__
   * - **Functional Specifications**
     - Requirements ``[FUNC-001]``..``[FUNC-005]``, behavioral contracts, and interfaces.
     - `Functional Specifications <functional/spec.rst>`__
   * - **Technical Architecture**
     - OpenSSL 3.5+ ``EVP_PKEY`` bindings, ``libsodium`` guarded memory, threat model, and release protocol.
     - `Technical Architecture <technical/spec.rst>`__
   * - **Architecture Decisions**
     - Immutable Architecture Decision Records and trade-off analyses.
     - `Architecture Decisions <adrs/index.rst>`__
   * - **Project Roadmap**
     - Sequenced phase milestones, delivery tracking, and verification audits.
     - `Project Roadmap <project/roadmap.rst>`__
   * - **User Guides**
     - Integration guides, code examples, and API tutorials.
     - `User Manual <user/index.rst>`__
   * - **Crystal API Reference**
     - Compiler-generated API documentation covering all classes, enums, and modules.
     - `Crystal API Reference <technical/api/index.html>`__

.. toctree::
   :maxdepth: 2
   :caption: Documentation Suite

   business/spec
   functional/spec
   technical/spec
   adrs/index
   project/roadmap
   user/index

Indices and tables
------------------

* :ref:`genindex`
* :ref:`search`
