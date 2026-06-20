import os
import binascii
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# 2. Preliminaries


# 2.1. X3DH parameters
# curve: X25519 or X448 | hash: SHA-256 | info: "MyProtocol"
# For example, an application could choose curve as X25519... and info as "MyProtocol".


INFO = b"MyProtocol"

def Encode(pk):
    """
    An application must additionally define an encoding function Encode(PK) to 
    encode an X25519 or X448 public key PK into a byte sequence.
    """

    # ALGORITHM: Raw Public Key Serialization
    # Converts the elliptic curve public key object into its raw, 32-byte representation.
    
    return pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

def DH(private_key, public_key):
    """
    DH(PK1, PK2) represents a byte sequence which is the shared secret 
    output from an Elliptic Curve Diffie-Hellman function...
    """
    # ALGORITHM: X25519 ECDH (Elliptic Curve Diffie-Hellman) Key Exchange
    # Computes the raw scalar multiplication shared secret over Curve25519.
    return private_key.exchange(public_key)

def KDF(key_material):
    """
    KDF(KM) represents 32 bytes of output from the HKDF algorithm [3]
    HKDF input key material = F || KM ... F is a byte sequence containing 32 0xFF bytes if curve is X25519
    HKDF salt = A zero-filled byte sequence with length equal to the hash output length.
    HKDF info = The info parameter from Section 2.1.
    """

    # ALGORITHM: HKDF-SHA256 (HMAC-based Extract-and-Expand Key Derivation Function)
    # Extracts entropy from the concatenated DH outputs and expands it into a cryptographically strong 32-byte key.

    F = b'\xFF' * 32
    hkdf_input = F + key_material
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'\x00' * 32,
        info=INFO
    )
    return hkdf.derive(hkdf_input)

# Helper function to print keys nicely in the console

def print_key(name, priv_key=None, pub_key=None):
    print(f"\n--- {name} ---")
    if priv_key:
        # ALGORITHM: Raw Private Key Serialization
        priv_bytes = priv_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        print(f" Private: {binascii.hexlify(priv_bytes).decode()}")
    if pub_key:
        print(f" Public:  {binascii.hexlify(Encode(pub_key)).decode()}")



# MAIN EXECUTION FLOW


if __name__ == "__main__":
    
    print("\n X3DH PROTOCOL EXECUTION WITH PDF SOURCE MAPPING \n")
    
    print(f"Parameters loaded -> Curve: X25519, Hash: SHA-256, Info: {INFO.decode()}")


    # 2.4. Keys


    print("\nGENERATING LONG-TERM & PREKEYS\n")
    
    # Each party has a long-term identity public key (IKA for Alice, IKB for Bob).
    print("-> Generating IKA (Alice) and IKB (Bob)...")
    
    print("   Generating Alice Identity Key... ", end="")
    IKA_private = x25519.X25519PrivateKey.generate()
    IKA_public = IKA_private.public_key()
    print("[ALG: Curve X25519 Key Gen]")
    
    print("   Generating Bob Identity Key... ", end="")
    IKB_private = x25519.X25519PrivateKey.generate()
    IKB_public = IKB_private.public_key()
    print("[ALG: Curve X25519 Key Gen]")


    # Sig(PK, M) represents a byte sequence that is an XEdDSA signature...
    # (Note: Using standard Ed25519 for Bob's signing capability to mimic XEdDSA)

    print("   Generating Bob Signing Identity Key... ", end="")
    IKB_sign_private = ed25519.Ed25519PrivateKey.generate()
    IKB_sign_public = IKB_sign_private.public_key()
    print("[ALG: Curve Ed25519 Key Gen]")

    print_key("Alice Identity Key (IKA)", IKA_private, IKA_public)
    print_key("Bob Identity Key (IKB)", IKB_private, IKB_public)

    
    # 3.2. Publishing keys
    

    print("\nPHASE 1: BOB PUBLISHES PREKEYS TO SERVER\n")
    
    # Bob's signed prekey SPKB

    print("-> Bob generates signed prekey SPKB... ", end="")
    SPKB_private = x25519.X25519PrivateKey.generate()
    SPKB_public = SPKB_private.public_key()
    print("[ALG: Curve X25519 Key Gen]")
    print_key("Bob Signed Prekey (SPKB)", SPKB_private, SPKB_public)

    # Bob's prekey signature Sig(IKB, Encode(SPKB))

    print("\n-> Bob generates prekey signature Sig(IKB, Encode(SPKB))... ", end="")
    spkb_encoded = Encode(SPKB_public)
    signature = IKB_sign_private.sign(spkb_encoded)
    print("[ALG: Ed25519 Signature Gen]")
    print(f"    {binascii.hexlify(signature).decode()}")

    # A set of Bob's one-time prekeys (OPKB...)

    print("\n-> Bob generates one-time prekey OPKB... ", end="")
    OPKB_private = x25519.X25519PrivateKey.generate()
    OPKB_public = OPKB_private.public_key()
    print("[ALG: Curve X25519 Key Gen]")
    print_key("Bob One-Time Prekey (OPKB)", OPKB_private, OPKB_public)

    print("\n -> Bob publishes a set of elliptic curve public keys to the server.")

    
    # 3.3. Sending the initial message
   

    print("\nPHASE 2: ALICE FETCHES BUNDLE & INITIATES\n")
    print(" -> Alice contacts the server and fetches a 'prekey bundle'...")
    
    # Server provides Bob's bundle to Alice

    bundle_IKB = IKB_public
    bundle_SPKB = SPKB_public
    bundle_signature = signature
    bundle_OPKB = OPKB_public 

    # Alice verifies the prekey signature and aborts the protocol if verification fails.

    try:
        print(" -> Alice verifies the prekey signature... ", end="")
        IKB_sign_public.verify(bundle_signature, Encode(bundle_SPKB))
        print("[ALG: Ed25519 Signature Verification]")
        print("    Verification SUCCESS: Alice verifies the prekey signature.")
    except Exception:
        print("\n -> Verification FAILED: Alice aborts the protocol.")
        exit(1)

    # Alice then generates an ephemeral key pair with public key EKA.

    print("\n -> Alice generates an ephemeral key pair with public key EKA... ", end="")
    EKA_private = x25519.X25519PrivateKey.generate()
    EKA_public = EKA_private.public_key()
    print("[ALG: Curve X25519 Key Gen]")

    # DH Calculations

    print("\n -> Alice calculates DH1, DH2, DH3, and DH4... ", end="")
    print("[ALG: 4x X25519 ECDH Operations]")
    DH1_alice = DH(IKA_private, bundle_SPKB)   # DH1 = DH(IKA, SPKB) -> Auth for Alice identity
    DH2_alice = DH(EKA_private, bundle_IKB)    # DH2 = DH(EKA, IKB)  -> Forward secrecy component
    DH3_alice = DH(EKA_private, bundle_SPKB)   # DH3 = DH(EKA, SPKB) -> Forward secrecy component
    DH4_alice = DH(EKA_private, bundle_OPKB)   # DH4 = DH(EKA, OPKB) -> One-time forward secrecy guarantee

    print(f"    DH1: {binascii.hexlify(DH1_alice).decode()}")
    print(f"    DH2: {binascii.hexlify(DH2_alice).decode()}")
    print(f"    DH3: {binascii.hexlify(DH3_alice).decode()}")
    print(f"    DH4: {binascii.hexlify(DH4_alice).decode()}")

    # SK = KDF(DH1 || DH2 || DH3 || DH4)

    print("\n -> Alice calculates SK = KDF(DH1 || DH2 || DH3 || DH4)... ", end="")
    KM_alice = DH1_alice + DH2_alice + DH3_alice + DH4_alice
    SK_alice = KDF(KM_alice)
    print("[ALG: HKDF-SHA256 Derivation]")
    print(f"    {binascii.hexlify(SK_alice).decode()}")

    # After calculating SK, Alice deletes her ephemeral private key and the DH outputs.

    print("\n -> Alice deletes her ephemeral private key and the DH outputs.")
    del EKA_private, DH1_alice, DH2_alice, DH3_alice, DH4_alice

    # AD = Encode(IKA) || Encode(IKB)

    print("\n -> Alice calculates 'associated data' byte sequence AD = Encode(IKA) || Encode(IKB).")
    AD = Encode(IKA_public) + Encode(bundle_IKB)
    
    # An initial ciphertext encrypted with some AEAD encryption scheme...

    print("\n -> Alice encrypts the initial ciphertext using an AEAD scheme... ", end="")
    aesgcm_alice = AESGCM(SK_alice)
    nonce = os.urandom(12) # Cryptographically secure 12-byte initialization vector (IV)
    plaintext = b"Hello Bob! This is an encrypted asynchronous payload via X3DH."
    ciphertext = aesgcm_alice.encrypt(nonce, plaintext, AD)
    print("[ALG: 256-bit AES-GCM Encryption]")

    print(f"    Ciphertext: {binascii.hexlify(ciphertext).decode()}")


    
    # 3.4. Receiving the initial message
    

    print("\nPHASE 3: BOB RECEIVES AND DECRYPTS\n")
    
    # Upon receiving Alice's initial message, Bob retrieves Alice's identity key and ephemeral key...

    print(" -> Bob receives message and retrieves Alice's IKA and EKA.")
    received_IKA = IKA_public
    received_EKA = EKA_public

    # Using these keys, Bob repeats the DH and KDF calculations...

    print("\n -> Bob repeats the DH calculations to derive SK... ", end="")
    print("[ALG: 4x Reciprocal X25519 ECDH Operations]")
    DH1_bob = DH(SPKB_private, received_IKA)
    DH2_bob = DH(IKB_private, received_EKA)
    DH3_bob = DH(SPKB_private, received_EKA)
    DH4_bob = DH(OPKB_private, received_EKA)
    
    print(" -> Bob derives SK from combined DH segments... ", end="")
    KM_bob = DH1_bob + DH2_bob + DH3_bob + DH4_bob
    SK_bob = KDF(KM_bob)
    print("[ALG: HKDF-SHA256 Derivation]")
    print(f"    Bob's derived SK: {binascii.hexlify(SK_bob).decode()}")

    # Bob then constructs the AD byte sequence using IKA and IKB...

    print("\n -> Bob constructs the AD byte sequence using IKA and IKB.")
    AD_bob = Encode(received_IKA) + Encode(IKB_public)
    
    # Finally, Bob attempts to decrypt the initial ciphertext using SK and AD.

    try:
        print("\n -> Bob attempts to decrypt the initial ciphertext using SK and AD... ", end="")
        aesgcm_bob = AESGCM(SK_bob)
        decrypted = aesgcm_bob.decrypt(nonce, ciphertext, AD_bob)
        print("[ALG: 256-bit AES-GCM Decryption]")
        print("\n -> SUCCESS: The initial ciphertext decrypts successfully. Protocol is complete for Bob.")
        print(f" -> DECRYPTED MESSAGE: '{decrypted.decode()}'")
    except Exception:

        # If the initial ciphertext fails to decrypt, then Bob aborts the protocol and deletes SK.

        print("\n -> FAILURE: Ciphertext fails to decrypt. Bob aborts and deletes SK.")
        del SK_bob
        exit(1)

    # Bob deletes any one-time prekey private key that was used, for forward secrecy.

    del OPKB_private
    print(" -> Bob deletes the one-time prekey (OPKB) private key for forward secrecy.")

    print("\n HANDSHAKE COMPLETE \n")