import os
import struct
import socket

from typing import Type, Union, Tuple
from enum import IntEnum
from abc import abstractmethod
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.fernet import Fernet


class PacketType(IntEnum):
    @abstractmethod
    def __str__(self) -> str:
        return self.name


class Packet:
    def __init__(self, packet_id: int, packet_type: PacketType) -> None:
        self.id = packet_id
        self.type = packet_type

    def get_id(self) -> int:
        return self.id

    def get_packet_type(self) -> PacketType:
        return self.type

    def __str__(self) -> str:
        return f'Packet Type: {self.type}, Packet ID: {self.id}'


class PacketSerializer:
    @staticmethod
    @abstractmethod
    def serialize(packet: Union[Type[Packet], Packet], private_key=None, public_key=None) -> bytes:
        raise NotImplementedError


class PacketDataDeserializer:
    @staticmethod
    @abstractmethod
    def deserialize(data: bytes) -> Union[Type[Packet], Packet]:
        raise NotImplementedError


class EncryptedPacketSerializer:
    @staticmethod
    def serialize(packet: Packet, aes_key, hmac_key, serializer: Type[PacketSerializer],
                  private_key=None, public_key=None) -> bytes:
        packet_bytes = serializer.serialize(packet, private_key=private_key, public_key=public_key)
        nonce = os.urandom(16)

        algorithm = algorithms.AES(aes_key)
        cipher = Cipher(algorithm, modes.CTR(nonce))
        encryptor = cipher.encryptor()

        encrypted_packet = encryptor.update(packet_bytes) + encryptor.finalize()
        len_encrypted_packet = struct.pack('!I', len(encrypted_packet))

        h = hmac.HMAC(hmac_key, hashes.SHA256())
        h.update(nonce + len_encrypted_packet + encrypted_packet)
        tag = h.finalize()

        return nonce + len_encrypted_packet + encrypted_packet + tag


class EncryptedPacketDeserializer:
    @staticmethod
    def deserialize(s: socket, aes_key, hmac_key, deserializer: Type[PacketDataDeserializer]) \
            -> Union[Type[Packet], Packet]:
        nonce_and_len = s.recv(20)
        if not nonce_and_len:
            raise ConnectionAbortedError('Connection closed')

        nonce, len_packet = struct.unpack('!16sI', nonce_and_len)
        encrypted_packet = s.recv(len_packet)
        tag = s.recv(32)

        h = hmac.HMAC(hmac_key, hashes.SHA256())
        h.update(nonce_and_len + encrypted_packet)
        h.verify(tag)

        algorithm = algorithms.AES(aes_key)
        cipher = Cipher(algorithm, modes.CTR(nonce))
        decryptor = cipher.decryptor()

        decrypted_packet = decryptor.update(encrypted_packet) + decryptor.finalize()
        return deserializer.deserialize(decrypted_packet)


class CentralizedEncryption:
    @staticmethod
    def sign_bytes(private_key_rsa: RSAPrivateKey, data: bytes) -> bytes:
        return private_key_rsa.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    @staticmethod
    def verify_signature(public_key_rsa: RSAPublicKey, sig: bytes, data: bytes) -> bool:
        try:
            public_key_rsa.verify(
                sig,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def encrypt_bytes(public_key_rsa: RSAPublicKey, data: bytes) -> bytes:
        return public_key_rsa.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def decrypt_bytes(private_key_rsa: RSAPrivateKey, data: bytes) -> bytes:
        return private_key_rsa.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def _serialize_msg(uid: bytes, subject: bytes, body: bytes) -> bytes:
        len_subject, len_body, len_uid = len(subject), len(body), len(uid)
        separate_data = [len_uid, uid, len_subject, subject, len_body, body]
        separate_format_string = '!H%dsH%dsH%ds' % (len_uid, len_subject, len_body)
        return struct.pack(separate_format_string, *separate_data)

    @staticmethod
    def sign_msg(private_key_rsa, peer_public_key, uid: str, subject: str, body: str) -> bytes:
        uid_bytes, subject_bytes, body_bytes = uid.encode('utf-8'), subject.encode('utf-8'), body.encode('utf-8')

        msg_bytes = CentralizedEncryption._serialize_msg(uid_bytes, subject_bytes, body_bytes)
        sig = CentralizedEncryption.sign_bytes(private_key_rsa, msg_bytes)
        len_and_sig = struct.pack('!H%ds' % len(sig), len(sig), sig)

        # symmetric key generation and encryption with peer's public key
        symmetric_key = Fernet.generate_key()
        f = Fernet(symmetric_key)
        encrypted_symmetric_key = CentralizedEncryption.encrypt_bytes(peer_public_key, symmetric_key)

        len_enc_sym_key = len(encrypted_symmetric_key)
        len_and_enc_sym_key = struct.pack('!H%ds' % len_enc_sym_key, len_enc_sym_key, encrypted_symmetric_key)

        encrypted_subject = f.encrypt(subject_bytes)
        encrypted_body = f.encrypt(body_bytes)

        serialized_msg_bytes = CentralizedEncryption._serialize_msg(uid_bytes, encrypted_subject, encrypted_body)

        return serialized_msg_bytes + len_and_sig + len_and_enc_sym_key

    @staticmethod
    def verify_signed_msg(public_key_rsa, private_key, uid: bytes, subject: bytes, body: bytes, sig: bytes, f_key: bytes) \
            -> Tuple[bytes, bytes] | None:
        symmetric_key = CentralizedEncryption.decrypt_bytes(private_key, f_key)
        f = Fernet(symmetric_key)
        decrypted_subject = f.decrypt(subject)
        decrypted_body = f.decrypt(body)
        msg_bytes = CentralizedEncryption._serialize_msg(uid, decrypted_subject, decrypted_body)
        if not CentralizedEncryption.verify_signature(public_key_rsa, sig, msg_bytes):
            return None
        else:
            return decrypted_subject, decrypted_body
