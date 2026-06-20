# 🔐 Signal Protocol Suite in Python

### X3DH Key Agreement & Double Ratchet Secure Messaging

A comprehensive implementation of the core cryptographic protocols used by modern end-to-end encrypted messaging systems such as Signal.

This repository contains both **educational (Demo)** and **enhanced production-oriented implementations** of:

* X3DH (Extended Triple Diffie-Hellman)
* Double Ratchet Algorithm

Together, these protocols provide secure asynchronous key exchange, forward secrecy, post-compromise security, and authenticated end-to-end encrypted messaging.

---

## ✨ Features

### 🔑 X3DH Protocol

* X25519 Elliptic Curve Diffie-Hellman
* Ed25519 Digital Signatures
* Signed Prekeys
* One-Time Prekeys
* HKDF-SHA256 Key Derivation
* AES-256-GCM Encryption
* Identity Authentication
* Asynchronous Session Establishment

### 🔄 Double Ratchet Algorithm

* Diffie-Hellman Ratchet
* Symmetric-Key Ratchet
* Forward Secrecy
* Post-Compromise Security
* Message Authentication
* Tamper Detection
* Replay Resistance
* Out-of-Order Message Handling
* Session Persistence
* Serialization & Restoration

---

## 📖 Overview

Secure messaging systems require two major cryptographic building blocks:

### X3DH

Establishes an initial shared secret between two users.

### Double Ratchet

Continuously evolves encryption keys after every message exchange.

The workflow is:

```text
Identity Verification
        │
        ▼
X3DH Key Agreement
        │
        ▼
Shared Secret
        │
        ▼
Double Ratchet
        │
        ▼
Secure Messaging
```

---

# 🔑 X3DH Architecture

```text
                        Bob

         Identity Key (IKB)
         Signed Prekey (SPKB)
         One-Time Prekey (OPKB)

                     │
                     ▼

            Publish Prekey Bundle

                     │
                     ▼

                    Alice

      Downloads Bob's Prekey Bundle

      Verifies Signature

      Generates Ephemeral Key (EKA)

      Computes:

      DH1 = DH(IKA, SPKB)
      DH2 = DH(EKA, IKB)
      DH3 = DH(EKA, SPKB)
      DH4 = DH(EKA, OPKB)

                     │
                     ▼

      KM = DH1 || DH2 || DH3 || DH4

                     │
                     ▼

               HKDF-SHA256

                     │
                     ▼

              Shared Secret

                     │
                     ▼

             AES-256-GCM
```

---

# 🔄 Double Ratchet Architecture

```text
                  X3DH Shared Secret
                           │
                           ▼

                     Root Key (RK)

                           │

             ┌─────────────┴─────────────┐
             │                           │
             ▼                           ▼

       Sending Chain              Receiving Chain
          (CKs)                       (CKr)

             │                           │
             ▼                           ▼

       Message Keys                Message Keys
           (MK)                        (MK)

             │
             ▼

        AES-256-GCM

             │
             ▼

     Secure Message Exchange
```

---

# ⚙️ Requirements

* Python 3.10+
* cryptography

---

# 📦 Installation

Install required dependency:

```bash
pip install cryptography
```

Verify installation:

```bash
pip show cryptography
```

---

# 🔐 Cryptographic Components

| Component            | Purpose                     |
| -------------------- | --------------------------- |
| X25519               | Diffie-Hellman Key Exchange |
| Ed25519              | Digital Signatures          |
| HKDF-SHA256          | Key Derivation              |
| HMAC-SHA256          | Chain Key Derivation        |
| AES-256-GCM          | Authenticated Encryption    |
| Secure Random Nonces | Encryption Security         |

---

# 🚀 X3DH Protocol Flow

### Phase 1 — Bob Publishes

Bob generates:

* Identity Key Pair
* Signed Prekey Pair
* One-Time Prekey Pair

Bob signs the Signed Prekey and publishes:

* Identity Key
* Signed Prekey
* Signature
* One-Time Prekey

---

### Phase 2 — Alice Initiates

Alice verifies Bob's signature and computes:

```text
DH1 = DH(IKA, SPKB)
DH2 = DH(EKA, IKB)
DH3 = DH(EKA, SPKB)
DH4 = DH(EKA, OPKB)
```

Combines all secrets:

```text
KM = DH1 || DH2 || DH3 || DH4
```

Derives:

```text
SK = HKDF(KM)
```

Encrypts the initial message.

---

### Phase 3 — Bob Receives

Bob performs identical computations and derives the same shared secret.

Result:

```text
Handshake Complete
```

---

# 🔄 Double Ratchet Workflow

After X3DH:

```text
Shared Secret
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

Each message generates a new encryption key.

---

# 🧪 Testing

The implementation includes:

### X3DH Tests

* Signature Verification
* Shared Secret Agreement
* Encryption & Decryption

### Double Ratchet Tests

* Basic Messaging
* DH Ratchet Triggering
* Sequential Messaging
* Out-of-Order Delivery
* Tampered Message Detection
* Session Persistence
* Serialization
* Stress Testing

Expected output:

```text
All tests passed.
```

---

# 🛡 Security Properties

### Forward Secrecy

Compromise of a current key does not reveal past messages.

### Post-Compromise Security

Security automatically recovers after future ratchet updates.

### Authentication

Ed25519 signatures verify identities.

### Integrity

AES-GCM detects message tampering.

### Confidentiality

Only intended recipients can decrypt messages.

### Replay Resistance

Every message uses a unique ratchet-derived key.

---

# ⚠️ Disclaimer

This project is intended for:

* Education
* Research
* Cryptography Learning
* Academic Demonstration

The Production implementation follows secure design principles but should undergo additional security review, testing, and auditing before deployment in real-world environments.

---

# 📚 References

### X3DH Specification

https://signal.org/docs/specifications/x3dh/

### Double Ratchet Specification

https://signal.org/docs/specifications/doubleratchet/

### Signal Protocol

https://signal.org

---

# 👨‍💻 Author

Developed as a complete educational and production-oriented implementation of:

* X3DH Key Agreement Protocol
* Signal Double Ratchet Algorithm

using Python and the Cryptography library.


---

## From Initial Trust to Continuous Secure Messaging

**Identity Authentication → X3DH Handshake → Shared Secret Generation → Double Ratchet → End-to-End Encrypted Communication**
