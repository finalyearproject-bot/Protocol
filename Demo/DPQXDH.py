import base64
import os
from dataclasses import dataclass
from typing import Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.hashes import SHA512

@dataclass
class PreKeyBundle:
    identity_public: str
    signed_pre_key_public: str
    pq_pre_key_public: str

class MockKyber1024:
    @staticmethod
    def generate_keypair():
        return os.urandom(1568), os.urandom(3168)

    @staticmethod
    def encap_secret(public_key):
        ciphertext = os.urandom(1568)
        hkdf = HKDF(algorithm=SHA512(), length=32, salt=b"", info=b"mock_kem")
        return ciphertext, hkdf.derive(public_key + ciphertext)

    @staticmethod
    def decap_secret(ciphertext, public_key):
        hkdf = HKDF(algorithm=SHA512(), length=32, salt=b"", info=b"mock_kem")
        return hkdf.derive(public_key + ciphertext)

def derive_master_key(dh1: bytes, dh2: bytes, dh3: bytes, pq_ss: bytes) -> bytes:
    key_material = dh1 + dh2 + dh3 + pq_ss
    hkdf = HKDF(algorithm=SHA512(), length=32, salt=bytes(64), info=b"Protocol_CURVE25519_SHA512_KYBER1024")
    return hkdf.derive(key_material)

def encode_pub(key) -> str:
    return base64.b64encode(key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

def decode_pub(b64_str: str):
    return x25519.X25519PublicKey.from_public_bytes(base64.b64decode(b64_str))

def run_verbose():
    print("\n" + "=" * 65)
    print(" PQXDH HYBRID PROTOCOL: FULL STEP-BY-STEP TRACE")
    print("=" * 65 + "\n")

    kem = MockKyber1024()

    # --- PHASE 1 ---
    print(">>> PHASE 1: BOB PUBLISHES PREKEY BUNDLE")
    bob_id_priv = x25519.X25519PrivateKey.generate()
    bob_spk_priv = x25519.X25519PrivateKey.generate()
    bob_pq_pub, bob_pq_priv = kem.generate_keypair()
    
    bundle = PreKeyBundle(
        identity_public=encode_pub(bob_id_priv.public_key()),
        signed_pre_key_public=encode_pub(bob_spk_priv.public_key()),
        pq_pre_key_public=base64.b64encode(bob_pq_pub).decode()
    )
    print(f"  [+] Bob's ID Key (Base64) : {bundle.identity_public[:20]}...")
    print(f"  [+] Bob's SPK (Base64)    : {bundle.signed_pre_key_public[:20]}...")
    print(f"  [+] Bob's PQ Key (Base64) : {bundle.pq_pre_key_public[:20]}...\n")

    # --- PHASE 2 ---
    print(">>> PHASE 2: ALICE INITIATES HANDSHAKE")
    alice_id_priv = x25519.X25519PrivateKey.generate()
    alice_ek_priv = x25519.X25519PrivateKey.generate()
    print(f"  [+] Alice generated Identity Key and Ephemeral Key.")
    
    bob_spk_pub_obj = decode_pub(bundle.signed_pre_key_public)
    bob_id_pub_obj = decode_pub(bundle.identity_public)
    
    dh1_a = alice_id_priv.exchange(bob_spk_pub_obj)
    dh2_a = alice_ek_priv.exchange(bob_id_pub_obj)
    dh3_a = alice_ek_priv.exchange(bob_spk_pub_obj)
    print(f"  [+] Classical DH1 (IK_a + SPK_b): {dh1_a.hex()[:16]}...")
    print(f"  [+] Classical DH2 (EK_a + IK_b) : {dh2_a.hex()[:16]}...")
    print(f"  [+] Classical DH3 (EK_a + SPK_b): {dh3_a.hex()[:16]}...")
    
    ct, alice_pq_ss = kem.encap_secret(base64.b64decode(bundle.pq_pre_key_public))
    print(f"  [+] Post-Quantum SS Encapsulated: {alice_pq_ss.hex()[:16]}...")
    
    alice_master = derive_master_key(dh1_a, dh2_a, dh3_a, alice_pq_ss)
    print(f"  ==> ALICE'S MASTER SECRET: {alice_master.hex()[:24]}...\n")

    # --- PHASE 3 ---
    print(">>> PHASE 3: BOB RECEIVES AND DECAPSULATES")
    dh1_b = bob_spk_priv.exchange(alice_id_priv.public_key())
    dh2_b = bob_id_priv.exchange(alice_ek_priv.public_key())
    dh3_b = bob_spk_priv.exchange(alice_ek_priv.public_key())
    print(f"  [+] Bob recomputed Classical DH1, DH2, DH3.")
    
    bob_pq_ss = kem.decap_secret(ct, bob_pq_pub)
    print(f"  [+] Bob Decapsulated PQ SS      : {bob_pq_ss.hex()[:16]}...")
    
    bob_master = derive_master_key(dh1_b, dh2_b, dh3_b, bob_pq_ss)
    print(f"  ==> BOB'S MASTER SECRET  : {bob_master.hex()[:24]}...\n")

    # --- VERIFICATION ---
    print(">>> VERIFICATION")
    if alice_master == bob_master:
        print("  [SUCCESS] Both parties derived the exact same Hybrid Key!")
    else:
        print("  [FAILED] Keys do not match.")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    run_verbose()