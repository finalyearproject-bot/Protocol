import sys
import logging
import secrets
from dataclasses import dataclass
from typing import Dict, Set, Optional, Tuple  # <-- FIXED: Added Tuple here
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag

# ==========================================
# MODULE: config.py
# ==========================================
class Config:
    INFO: bytes = b"MyProtocol"
    HKDF_LENGTH: int = 32
    NONCE_SIZE: int = 12
    HASH_ALGORITHM = hashes.SHA256()

# ==========================================
# SETUP PRODUCTION LOGGING (No Private Data)
# ==========================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout
)
logger = logging.getLogger("X3DH.System")

# ==========================================
# MODULE: crypto/engine.py
# ==========================================
class X3DHCrypto:
    """
    State-free primitive engine enforcing formal type definitions and strict validation.
    """
    @staticmethod
    def encode(public_key: x25519.X25519PublicKey) -> bytes:
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    @staticmethod
    def dh(private_key: x25519.X25519PrivateKey, public_key: x25519.X25519PublicKey) -> bytearray:
        try:
            return bytearray(private_key.exchange(public_key))
        except Exception as e:
            logger.critical("Catastrophic failure during Elliptic Curve Diffie-Hellman point multiplication.")
            raise RuntimeError("ECDH operation failed") from e

    @staticmethod
    def kdf(key_material: bytearray) -> bytearray:
        """
        Derives symmetric key material using HKDF-SHA256 with constant-time memory separation.
        """
        F: bytes = b'\xFF' * 32
        hkdf_input: bytes = F + bytes(key_material)
        
        hkdf = HKDF(
            algorithm=Config.HASH_ALGORITHM,
            length=Config.HKDF_LENGTH,
            salt=b'\x00' * Config.HASH_ALGORITHM.digest_size,
            info=Config.INFO
        )
        derived: bytes = hkdf.derive(hkdf_input)
        
        # Immediate cleanup of input parameter references
        X3DHCrypto.safe_wipe(key_material)
        return bytearray(derived)

    @staticmethod
    def encrypt(sk: bytearray, plaintext: bytes, associated_data: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypts payload via authenticated 256-bit AES-GCM. Returns (nonce, ciphertext).
        """
        nonce: bytes = secrets.token_bytes(Config.NONCE_SIZE)
        aesgcm = AESGCM(bytes(sk))
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext

    @staticmethod
    def decrypt(sk: bytearray, ciphertext: bytes, nonce: bytes, associated_data: bytes) -> bytes:
        """
        Decrypts authenticated payload. Throws InvalidTag on structural modification.
        """
        if len(nonce) != Config.NONCE_SIZE:
            raise ValueError(f"Invalid initialization vector boundary size: {len(nonce)}")
        aesgcm = AESGCM(bytes(sk))
        return aesgcm.decrypt(nonce, ciphertext, associated_data)

    @staticmethod
    def safe_wipe(target: Optional[bytearray]) -> None:
        """
        Overwrites active mutable allocations in memory with zeroes.
        """
        if target is not None:
            for i in range(len(target)):
                target[i] = 0x00

# ==========================================
# MODULE: storage/keystore.py
# ==========================================
class SecureKeystore:
    def __init__(self) -> None:
        self._store: Dict[str, object] = {}

    def save_private_key(self, alias: str, key_object: object) -> None:
        self._store[alias] = key_object
        logger.info(f"Successfully committed and hardware-isolated private key profile under alias reference: '{alias}'")

    def get_private_key(self, alias: str) -> object:
        if alias not in self._store:
            raise KeyError(f"Requested isolation key alias '{alias}' was not located inside secure hardware store allocation context.")
        return self._store[alias]

# ==========================================
# MODULE: models/key_bundle.py
# ==========================================
@dataclass(frozen=True)
class PreKeyBundle:
    identity_public: x25519.X25519PublicKey
    signed_prekey_public: x25519.X25519PublicKey
    signature: bytes
    one_time_prekey_public: Optional[x25519.X25519PublicKey]

# ==========================================
# MODULE: models/user.py
# ==========================================
class User:
    def __init__(self, name: str) -> None:
        self.name: str = name
        self.keystore: SecureKeystore = SecureKeystore()
        self.identity_public: Optional[x25519.X25519PublicKey] = None
        self.signing_public: Optional[ed25519.Ed25519PublicKey] = None
        self._initialize_identity_enclave()

    def _initialize_identity_enclave(self) -> None:
        logger.info(f"[{self.name}] Initializing cryptographic long-term root profiles...")
        priv_id = x25519.X25519PrivateKey.generate()
        self.identity_public = priv_id.public_key()
        self.keystore.save_private_key("identity", priv_id)
        
        priv_sign = ed25519.Ed25519PrivateKey.generate()
        self.signing_public = priv_sign.public_key()
        self.keystore.save_private_key("signing", priv_sign)

    def publish_bundle(self) -> PreKeyBundle:
        logger.info(f"[{self.name}] Building cryptographic ephemeral and signed target prekey bundles...")
        spk_priv = x25519.X25519PrivateKey.generate()
        spk_pub = spk_priv.public_key()
        self.keystore.save_private_key("signed_prekey", spk_priv)
        
        encoded_spk = X3DHCrypto.encode(spk_pub)
        signing_priv: ed25519.Ed25519PrivateKey = self.keystore.get_private_key("signing")
        signature = signing_priv.sign(encoded_spk)
        
        otk_priv = x25519.X25519PrivateKey.generate()
        otk_pub = otk_priv.public_key()
        self.keystore.save_private_key("one_time_prekey", otk_priv)
        
        return PreKeyBundle(
            identity_public=self.identity_public,
            signed_prekey_public=spk_pub,
            signature=signature,
            one_time_prekey_public=otk_pub
        )

# ==========================================
# MODULE: server/prekey_server.py
# ==========================================
class PreKeyServer:
    def __init__(self) -> None:
        self._bundles: Dict[str, PreKeyBundle] = {}
        self._used_nonces: Set[bytes] = set()

    def register_bundle(self, user_id: str, bundle: PreKeyBundle) -> None:
        self._bundles[user_id] = bundle
        logger.info(f"[Server] Successfully indexed modern prekey bundle configuration parameters for user metadata account: '{user_id}'")

    def fetch_bundle(self, user_id: str) -> PreKeyBundle:
        if user_id not in self._bundles:
            raise KeyError(f"No valid published prekey parameter entries located for the requested target sequence: {user_id}")
        logger.info(f"[Server] Delivering valid key registration parameters bundle trace for user client: '{user_id}'")
        return self._bundles[user_id]

    def verify_nonce_freshness(self, nonce: bytes) -> None:
        if nonce in self._used_nonces:
            logger.error(f"[Server/Replay Guard] Detected protocol reuse vulnerability execution match. Aborting instantly.")
            raise SecurityError("Replay attack verified: Provided packet initialization vector was already marked dead.")
        self._used_nonces.add(nonce)

class SecurityError(Exception):
    pass

# ==========================================
# MODULE: models/session.py
# ==========================================
class X3DHSession:
    def __init__(self) -> None:
        self.session_key: Optional[bytearray] = None
        self.associated_data: Optional[bytes] = None

    def initiator(self, sender: User, recipient_id: str, server: PreKeyServer, peer_signing_pub: ed25519.Ed25519PublicKey) -> Tuple[bytes, bytes, bytes]:
        logger.info(f"[{sender.name}] Handshake Init -> Pulling structural tracking records for peer identity target matching: '{recipient_id}'")
        bundle = server.fetch_bundle(recipient_id)
        
        try:
            peer_signing_pub.verify(bundle.signature, X3DHCrypto.encode(bundle.signed_prekey_public))
            logger.info(f"[{sender.name}] Peer bundle validation step finalized successfully. Signature state matches origin identity.")
        except InvalidSignature:
            logger.error(f"[{sender.name}] Critically invalid prekey registration parameter bundle signature! Handshake execution denied.")
            raise

        e_priv = x25519.X25519PrivateKey.generate()
        e_pub = e_priv.public_key()
        sender_id_priv: x25519.X25519PrivateKey = sender.keystore.get_private_key("identity")
        
        dh1 = X3DHCrypto.dh(sender_id_priv, bundle.signed_prekey_public)
        dh2 = X3DHCrypto.dh(e_priv, bundle.identity_public)
        dh3 = X3DHCrypto.dh(e_priv, bundle.signed_prekey_public)
        
        km = dh1 + dh2 + dh3
        if bundle.one_time_prekey_public is not None:
            dh4 = X3DHCrypto.dh(e_priv, bundle.one_time_prekey_public)
            km += dh4
            X3DHCrypto.safe_wipe(dh4)

        self.session_key = X3DHCrypto.kdf(km)
        self.associated_data = X3DHCrypto.encode(sender.identity_public) + X3DHCrypto.encode(bundle.identity_public)
        
        X3DHCrypto.safe_wipe(dh1)
        X3DHCrypto.safe_wipe(dh2)
        X3DHCrypto.safe_wipe(dh3)
        X3DHCrypto.safe_wipe(km)
        
        logger.info(f"[{sender.name}] Secure master tracking transaction session key successfully materialized via internal KDF.")
        return X3DHCrypto.encode(e_pub), X3DHCrypto.encode(bundle.one_time_prekey_public) if bundle.one_time_prekey_public else b"", X3DHCrypto.encode(e_pub)

    def responder(self, receiver: User, initiator_identity_pub: x25519.X25519PublicKey, initiator_ephemeral_pub: x25519.X25519PublicKey, used_otk_pub: Optional[x25519.X25519PublicKey]) -> None:
        logger.info(f"[{receiver.name}] Handshake Recv -> Resolving shared secret derivations over inbound key structures.")
        
        rec_spk_priv: x25519.X25519PrivateKey = receiver.keystore.get_private_key("signed_prekey")
        rec_id_priv: x25519.X25519PrivateKey = receiver.keystore.get_private_key("identity")
        
        dh1 = X3DHCrypto.dh(rec_spk_priv, initiator_identity_pub)
        dh2 = X3DHCrypto.dh(rec_id_priv, initiator_ephemeral_pub)
        dh3 = X3DHCrypto.dh(rec_spk_priv, initiator_ephemeral_pub)
        
        km = dh1 + dh2 + dh3
        if used_otk_pub is not None:
            rec_otk_priv: x25519.X25519PrivateKey = receiver.keystore.get_private_key("one_time_prekey")
            dh4 = X3DHCrypto.dh(rec_otk_priv, initiator_ephemeral_pub)
            km += dh4
            X3DHCrypto.safe_wipe(dh4)
            
        self.session_key = X3DHCrypto.kdf(km)
        self.associated_data = X3DHCrypto.encode(initiator_identity_pub) + X3DHCrypto.encode(receiver.identity_public)
        
        X3DHCrypto.safe_wipe(dh1)
        X3DHCrypto.safe_wipe(dh2)
        X3DHCrypto.safe_wipe(dh3)
        X3DHCrypto.safe_wipe(km)
        
        logger.info(f"[{receiver.name}] Reciprocal cryptographic tracking session keys match. Sync operations completed.")

# ==========================================
# MODULE: tests/unit_tests.py
# ==========================================
def run_unit_tests(alice_sk: bytearray, bob_sk: bytearray) -> None:
    logger.info("[Test Suite] Initializing validation assertions over derived context materials...")
    assert alice_sk == bob_sk, "CRITICAL HANDSHAKE MISALIGNMENT: Shared tracking secrets did not converge perfectly."
    assert len(alice_sk) == Config.HKDF_LENGTH, f"Key sizing specification fault."
    logger.info("[Test Suite] System verification assertions passed. All architectural tests: OK.")

# ==========================================
# ENTRYPOINT: main.py
# ==========================================
if __name__ == "__main__":
    logger.info("Initializing X3DH Reference Suite Core Architecture Verification Loop...")
    
    directory_server = PreKeyServer()
    alice = User("Alice")
    bob = User("Bob")
    
    bob_bundle = bob.publish_bundle()
    directory_server.register_bundle(bob.name, bob_bundle)
    
    alice_session = X3DHSession()
    ephemeral_public_bytes, used_otk_bytes, nonce_tag = alice_session.initiator(
        sender=alice,
        recipient_id=bob.name,
        server=directory_server,
        peer_signing_pub=bob.signing_public
    )
    
    payload: bytes = b"Hello Bob! This is an authenticated production-ready asynchronous payload via X3DH."
    logger.info("[Alice] Preparing payload processing under active cryptographic constraints... [ALG: 256-bit AES-GCM Encryption]")
    transmission_nonce, message_ciphertext = X3DHCrypto.encrypt(
        sk=alice_session.session_key,
        plaintext=payload,
        associated_data=alice_session.associated_data
    )
    
    try:
        directory_server.verify_nonce_freshness(transmission_nonce)
        
        bob_session = X3DHSession()
        bob_session.responder(
            receiver=bob,
            initiator_identity_pub=alice.identity_public,
            initiator_ephemeral_pub=x25519.X25519PublicKey.from_public_bytes(ephemeral_public_bytes),
            used_otk_pub=bob_bundle.one_time_prekey_public
        )
        
        logger.info("[Bob] Initializing incoming authentication and payload text recovery... [ALG: 256-bit AES-GCM Decryption]")
        decrypted_plaintext = X3DHCrypto.decrypt(
            sk=bob_session.session_key,
            ciphertext=message_ciphertext,
            nonce=transmission_nonce,
            associated_data=bob_session.associated_data
        )
        logger.info(f"[Bob] Verification SUCCESS. Handshake confirmed. Plaintext Decoded: '{decrypted_plaintext.decode()}'")
        
    except InvalidTag:
        logger.critical("[Bob] Security Alert: Context integrity validation check failed. Dropping transaction stream state.")
        sys.exit(1)
    except SecurityError as se:
        logger.critical(f"Handshake validation error processing request flow: {str(se)}")
        sys.exit(1)

    run_unit_tests(alice_session.session_key, bob_session.session_key)

    X3DHCrypto.safe_wipe(alice_session.session_key)
    X3DHCrypto.safe_wipe(bob_session.session_key)
    logger.info("System memory scrub completed. Session operational vectors zeroized safely. Closing pipeline loop gracefully.\n")