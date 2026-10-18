=============
User Personas
=============

Target Engineering Profiles
---------------------------

* **Security and Cryptography Engineers**: Require NIST-standardized lattice-based KEM and digital signature primitives with explicit memory zeroization, constant-time byte comparisons, deterministic seed expansion for NIST ACVP Known-Answer Tests, and domain-separated signature contexts.
* **FIDO2 and Identity Infrastructure Architects**: Require ``ML-DSA`` assertion signing and verification with protocol-specific ``context`` strings alongside hardware-backed and classical authenticators.
* **Systems and SRE Leads**: Require zero-dependency compilation and deployment against standard operating system packages (OpenSSL 3.5+ and ``libsodium`` on Fedora Linux and Alpine Linux containers).
