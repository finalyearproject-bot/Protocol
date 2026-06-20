# 🔐 Signal Protocol Implementation in Python

### X3DH Key Agreement + Double Ratchet Secure Messaging

A comprehensive implementation of the two core cryptographic protocols that power modern end-to-end encrypted messaging systems such as Signal.

This project demonstrates how secure communication can be established between two users through asynchronous key exchange and maintained through continuous cryptographic ratcheting.

---

## ✨ Features

### 🔑 X3DH Protocol

* X25519 Diffie-Hellman Key Exchange
* Ed25519 Digital Signatures
* Signed Prekeys
* One-Time Prekeys
* HKDF-SHA256 Key Derivation
* AES-256-GCM Encryption
* Authentication of Remote Identity
* Asynchronous Session Establishment

### 🔄 Double Ratchet Algorithm

* Diffie-Hellman Ratchet
* Symmetric-Key Ratchet
* Forward Secrecy
* Post-Compromise Security
* Out-of-Order Message Handling
* Replay Protection
* Message Authentication
* Tamper Detection
* Session Persistence
* Serialization & Restoration

---

# 📖 Overview

Modern secure messaging systems require two major components:

### 1. X3DH (Extended Triple Diffie-Hellman)

Used once during session initialization to establish a shared secret between two users.

### 2. Double Ratchet

Used after X3DH to continuously derive fresh encryption keys for every message exchanged.

Together, these protocols provide strong security guarantees while maintaining usability in real-world messaging applications.

---

# 🔑 X3DH Architecture

The X3DH protocol allows Alice and Bob to securely establish a shared secret even when Bob is offline.

```text
                    Bob
        ┌──────────────────────────┐
        │ Identity Key (IKB)       │
        │ Signed Prekey (SPKB)     │
        │ One-Time Prekey (OPKB)   │
        └─────────────┬────────────┘
                      │
               Publish Bundle
                      │
                      ▼

                    Alice

      Downloads Bob's Prekey Bundle

      Verifies SPKB Signature

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

           AES-256-GCM Encryption
```

---

# 🔄 Double Ratchet Architecture

After X3DH establishes the initial shared secret, the Double Ratchet algorithm takes over.

```text
                  X3DH Shared Secret
                           │
                           ▼

                    Root Key (RK)

                           │

            ┌──────────────┴──────────────┐
            │                             │
            ▼                             ▼

      Sending Chain                Receiving Chain
          (CKs)                        (CKr)

            │                             │
            ▼                             ▼

      Message Keys                  Message Keys
          (MK)                          (MK)

            │
            ▼

       AES-256-GCM

            │
            ▼

     Secure Message Exchange
```

Every message advances the ratchet and generates a completely new encryption key.

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

# 🚀 Protocol Flow

## Phase 1 — Bob Publishes Prekeys

Bob generates:

* Identity Key Pair (IKB)
* Signed Prekey Pair (SPKB)
* One-Time Prekey Pair (OPKB)

Bob signs the Signed Prekey using Ed25519 and publishes:

* Identity Key
* Signed Prekey
* Signature
* One-Time Prekey

---

## Phase 2 — Alice Initiates Session

Alice:

* Downloads Bob's Prekey Bundle
* Verifies Signature
* Generates Ephemeral Key Pair

Computes:

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

Uses the derived secret to encrypt the first message.

---

## Phase 3 — Bob Receives Message

Bob recomputes the same Diffie-Hellman values and derives the identical shared secret.

Result:

```text
Handshake Complete
```

---

## Phase 4 — Double Ratchet Begins

The X3DH shared secret becomes the initial Root Key.

From this point onward:

* Every message gets a unique encryption key.
* Future messages remain secure even if a current key is compromised.
* Past messages cannot be recovered from future keys.

---

# 🛡 Security Properties

## Forward Secrecy

Compromise of a current key does not expose previously transmitted messages.

---

## Post-Compromise Security

After a new Diffie-Hellman ratchet step, security is automatically restored.

---

## Authentication

Ed25519 signatures verify the authenticity of published prekeys.

---

## Confidentiality

Only the intended recipient can decrypt messages.

---

## Integrity

AES-256-GCM detects any modification to ciphertext or associated data.

---

## Replay Resistance

Every message uses a unique ratchet-derived key.

---

# 🧪 Testing

The implementation includes comprehensive testing for:

### X3DH

* Signature Verification
* Shared Secret Agreement
* Encryption & Decryption

### Double Ratchet

* Basic Messaging
* DH Ratchet Updates
* Sequential Messages
* Out-of-Order Delivery
* Serialization
* Session Restoration
* Tamper Detection
* Stress Testing

Expected result:

```text
All tests passed.
```

---

# ⚠️ Educational vs Production

This repository contains both:

### Demo Version

Designed for:

* Learning
* Research
* Academic Understanding
* Protocol Exploration

### Production Version

Enhanced with:

* Robust Session Management
* Secure State Persistence
* Serialization Support
* Improved Error Handling
* Message Key Storage
* Out-of-Order Message Recovery

---

# 📚 References

### Signal X3DH Specification

https://signal.org/docs/specifications/x3dh/

### Signal Double Ratchet Specification

https://signal.org/docs/specifications/doubleratchet/

### Signal Protocol

https://signal.org

---

# 👨‍💻 Author

Developed as a complete implementation of the Signal Protocol core cryptographic components:

* X3DH Key Agreement
* Double Ratchet Algorithm

using Python and the Cryptography library.

---

# ⭐ Support

If you found this project useful:

* Star the repository
* Fork the project
* Share with others
* Contribute improvements

---

## 🔐 From Initial Trust to Continuous Secure Messaging

This project demonstrates the complete lifecycle of secure communication:

**Identity Verification → Secure Key Exchange → Shared Secret Generation → Continuous Key Evolution → End-to-End Encrypted Messaging**

The same foundational concepts used by modern secure messaging systems are implemented here for educational and research purposes.
