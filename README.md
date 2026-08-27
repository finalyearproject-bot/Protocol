This is a great idea. Upgrading the documentation to reflect the post-quantum implementation ensures the repository remains cutting-edge.

Here is the fully merged and formatted `README.md`, integrating the PQXDH protocol seamlessly into your existing structure while maintaining its clean, professional layout:

---

# 🔐 Post-Quantum Signal Protocol Suite in Python

### PQXDH Key Agreement & Double Ratchet Secure Messaging

A comprehensive implementation of the core cryptographic protocols used by modern end-to-end encrypted messaging systems to secure communications against both classical and quantum threats.

This repository contains both **educational (Demo)** and **enhanced production-oriented implementations** of:

* X3DH (Extended Triple Diffie-Hellman)
* **PQXDH (Post-Quantum Extended Diffie-Hellman)**

* Double Ratchet Algorithm

Together, these protocols provide secure asynchronous key exchange, forward secrecy, post-compromise security, quantum resistance, and authenticated end-to-end encrypted messaging.

---

## ✨ Features

### 🔑 Key Agreement (X3DH & PQXDH)

* X25519 Elliptic Curve Diffie-Hellman


* **CRYSTALS-Kyber-1024 (ML-KEM) Key Encapsulation**

* **Hybrid Key Derivation (Classical + Post-Quantum)**

* Ed25519 Digital Signatures for Identity Authentication


* Signed Prekeys & One-Time Prekeys


* HKDF-SHA512 Key Derivation


* Asynchronous Session Establishment



### 🔄 Double Ratchet Algorithm

* Diffie-Hellman Ratchet
* Symmetric-Key Ratchet
* Forward Secrecy & Post-Compromise Security


* Message Authentication & Tamper Detection
* Replay Resistance & Out-of-Order Message Handling
* Session Persistence, Serialization & Restoration

---

## 📖 Overview

Secure messaging systems require two major cryptographic building blocks:

### PQXDH / X3DH

Establishes an initial shared secret between two users, blending classical discrete logarithm cryptography with lattice-based post-quantum cryptography.

### Double Ratchet

Continuously evolves encryption keys after every message exchange.

The workflow is:

```text
Identity Verification
        │
        ▼
PQXDH Key Agreement (Hybrid)
        │
        ▼
Hybrid Shared Secret
        │
        ▼
Double Ratchet
        │
        ▼
Secure Messaging

```

---

## 🔑 PQXDH Architecture

```text
                       Bob

         Identity Key (IKB - X25519)
         Signed Prekey (SPKB - X25519)
         One-Time Prekey (OPKB - X25519)
         Kyber Public Key (PQPKB - Kyber-1024)

                       │
                       ▼

             Publish Prekey Bundle

                       │
                       ▼

                     Alice

      Downloads Bob's Prekey Bundle

      Verifies XEdDSA Signatures

      Generates Ephemeral Key (EKA - X25519)
      Encapsulates PQ Secret (CT, SS)

      Computes Classical DH:
      DH1 = DH(IKA, SPKB)
      DH2 = DH(EKA, IKB)
      DH3 = DH(EKA, SPKB)
      DH4 = DH(EKA, OPKB) (If available)

                       │
                       ▼

      KM = DH1 || DH2 || DH3 || [DH4] || SS

                       │
                       ▼

                 HKDF-SHA512

                       │
                       ▼

             Hybrid Shared Secret

                       │
                       ▼

                 AES-256-GCM

```

---

## 🔄 Double Ratchet Architecture

```text
                 PQXDH Hybrid Shared Secret
                           │
                           ▼

                     Root Key (RK)

                           │

             ┌─────────────┴─────────────┐
             │                           │
             ▼                           ▼

       Sending Chain               Receiving Chain
          (CKs)                       (CKr)

             │                           │
             ▼                           ▼

       Message Keys                 Message Keys
           (MK)                         (MK)

             │
             ▼

        AES-256-GCM

             │
             ▼

     Secure Message Exchange

```

---

## ⚙️ Requirements

* Python 3.10+
* `cryptography`

* `liboqs-python` (Open Quantum Safe library for NIST FIPS 203 algorithms)



---

## 📦 Installation

Install required dependencies:

```bash
pip install cryptography liboqs-python

```

Verify installation:

```bash
pip show cryptography liboqs-python

```

---

## 🔐 Cryptographic Components

| Component | Purpose |
| --- | --- |
| **Kyber-1024** | **Post-Quantum Key Encapsulation (MLWE)**<br> |
| X25519 | Classical Diffie-Hellman Key Exchange

 |
| Ed25519 | Digital Signatures for Authentication

 |
| HKDF-SHA512 | Hybrid Key Derivation

 |
| HMAC-SHA256 | Chain Key Derivation |
| AES-256-GCM | Authenticated Encryption |

---

## 🚀 PQXDH Protocol Flow

### Phase 1 — Bob Publishes

Bob generates:

* Classical Identity, Signed Prekey, and One-Time Prekeys (X25519).


* Post-Quantum Last-Resort and One-Time Prekeys (Kyber-1024).



Bob signs the Signed Prekeys using his Identity Key and publishes the complete Hybrid Prekey Bundle to the server.

---

### Phase 2 — Alice Initiates

Alice verifies Bob's signatures and computes the classical exchanges:

```text
DH1 = DH(IKA, SPKB)
DH2 = DH(EKA, IKB)
DH3 = DH(EKA, SPKB)

```

She then encapsulates a post-quantum secret using Bob's Kyber Public Key, yielding a Ciphertext (`CT`) and a Shared Secret (`SS`).

She combines all secrets:

```text
KM = DH1 || DH2 || DH3 || SS

```

Derives the master secret via HKDF, and sends her Ephemeral Key (`EKA`) and the Ciphertext (`CT`) to Bob.

---

### Phase 3 — Bob Receives

Bob receives Alice's initialization message. He:

1. Recomputes the classical DH segments using his private keys.


2. Decapsulates the Ciphertext (`CT`) using his Kyber Private Key to recover the Post-Quantum Shared Secret (`SS`).


3. Derives the identical hybrid shared secret via HKDF.



Result: **Quantum-Resistant Handshake Complete**.

---

## 🔄 Double Ratchet Workflow

After PQXDH establishes the Hybrid Shared Secret:

```text
Hybrid Shared Secret
      │
      ▼
Root Key
      │
      ▼
Chain Keys
      │
      ▼
Message Keys
      │
      ▼
AES-GCM Encryption

```

Each message generates a new encryption key, ratcheting both DH and Symmetric chains forward.

---

## 🧪 Testing

The implementation includes:

### PQXDH / X3DH Tests

* XEdDSA Signature Verification
* Lattice-based Encapsulation & Decapsulation
* Hybrid Shared Secret Agreement
* Cross-Platform Mocking vs. Production `liboqs` bindings

### Double Ratchet Tests

* DH Ratchet Triggering
* Out-of-Order Delivery & Tampered Message Detection
* Session Persistence & Serialization

Expected output:

```text
All tests passed. Handshake Successful: True

```

---

## 🛡 Security Properties

### Quantum Resistance (HNDL Protection)

Protects against "Harvest-Now-Decrypt-Later" attacks. An adversary must break both the elliptic-curve problem and the lattice-based Module-LWE problem to derive the shared key.

### Forward Secrecy & Post-Compromise Security

Compromise of a current key does not reveal past messages, and security automatically recovers after future ratchet updates.

### Authentication & Integrity

Ed25519 signatures verify identities, and AES-GCM detects message tampering. *(Note: Authentication relies on classical ECC and is not currently quantum-secure against active adversaries)*.

---

## ⚠️ Disclaimer

This project is intended for Education, Research, and Cryptography Learning. The Production implementation utilizes audited libraries (`liboqs`), but the wrapper code should undergo additional security review, testing, and auditing before deployment in real-world, high-stakes environments.

---

## 📚 References

* **PQXDH Specification:** [Signal Post-Quantum Extended Diffie-Hellman](https://signal.org/docs/specifications/pqxdh/)
* **NIST FIPS 203:** Module-Lattice-Based Key-Encapsulation Mechanism Standard


* **Double Ratchet Specification:** [Signal Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)

---
