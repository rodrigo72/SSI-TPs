import struct
import socket

from typing import Type, Union
from packets import PacketType, Packet, PacketDataDeserializer, PacketSerializer, CentralizedEncryption


class ClientPacketType(PacketType):
    SEND = 0
    ASK_QUEUE = 1
    GET_MSG = 2
    PARAMS = 3
    PUBLIC_KEY = 4
    HANDSHAKE = 5
    GET_CERT = 6

    def __str__(self) -> str:
        return self.name


class ClientSendPacket(Packet):
    def __init__(self, packet_id: int, packet_uid: str | bytes, subject: str | bytes, body: str | bytes,
                 sig: bytes = None, encrypted_symmetric_key: bytes = None) -> None:
        super().__init__(packet_id, ClientPacketType.SEND)
        self.uid = packet_uid
        self.subject = subject
        self.body = body
        self.signature = sig
        self.encrypted_symmetric_key = encrypted_symmetric_key

    def __str__(self) -> str:
        return f'{super().__str__()}, Send to: {self.uid}, \nSubject: «{self.subject}», \nBody: «{self.body}»'


class ClientAskQueuePacket(Packet):
    def __init__(self, packet_id: int) -> None:
        super().__init__(packet_id, ClientPacketType.ASK_QUEUE)


class ClientGetMSGPacket(Packet):
    def __init__(self, packet_id: int, msg_num: int) -> None:
        super().__init__(packet_id, ClientPacketType.GET_MSG)
        self.msg_num = msg_num

    def __str__(self) -> str:
        return f'{super().__str__()}, Message number: {self.msg_num}'


class ClientParamsPacket(Packet):
    def __init__(self, packet_id: int, params: bytes) -> None:
        super().__init__(packet_id, ClientPacketType.PARAMS)
        self.params = params


class ClientPublicKeyPacket(Packet):
    def __init__(self, packet_id: int, public_key: bytes) -> None:
        super().__init__(packet_id, ClientPacketType.PUBLIC_KEY)
        self.public_key = public_key


class ClientHandshakePacket(Packet):
    def __init__(self, packet_id: int, signature: bytes, cert: bytes, salt: bytes) -> None:
        super().__init__(packet_id, ClientPacketType.HANDSHAKE)
        self.signature = signature
        self.cert = cert
        self.salt = salt


class ClientGetCertPacket(Packet):
    def __init__(self, packet_id: int, uid: str) -> None:
        super().__init__(packet_id, ClientPacketType.GET_CERT)
        self.uid = uid


class ClientPacketSerializer(PacketSerializer):
    @staticmethod
    def serialize(packet: Packet, private_key=None, public_key=None) -> bytes:
        format_string = '!BH'
        flat_data = [packet.type.value, packet.id]

        match packet.type:
            case ClientPacketType.SEND:
                if not isinstance(packet, ClientSendPacket):
                    raise ValueError('Invalid packet type')
                return ClientPacketSerializer._serialize_send(packet, format_string, flat_data, private_key, public_key)
            case ClientPacketType.ASK_QUEUE:
                if not isinstance(packet, ClientAskQueuePacket):
                    raise ValueError('Invalid packet type')
                return ClientPacketSerializer._serialize_ask_queue(format_string, flat_data)
            case ClientPacketType.GET_MSG:
                if not isinstance(packet, ClientGetMSGPacket):
                    raise ValueError('Invalid packet type')
                return ClientPacketSerializer._serialize_get_msg(packet, format_string, flat_data)
            case ClientPacketType.PARAMS:
                if not isinstance(packet, ClientParamsPacket):
                    raise ValueError('Invalid packet type')
                return ClientPacketSerializer._serialize_params(packet, format_string, flat_data)
            case ClientPacketType.PUBLIC_KEY:
                if not isinstance(packet, ClientPublicKeyPacket):
                    raise ValueError('Invalid packet type')
                return ClientPacketSerializer._serialize_public_key(packet, format_string, flat_data)
            case ClientPacketType.HANDSHAKE:
                if not isinstance(packet, ClientHandshakePacket):
                    raise ValueError('Invalid packet type')
                return ClientPacketSerializer._serialize_handshake(packet, format_string, flat_data)
            case ClientPacketType.GET_CERT:
                if not isinstance(packet, ClientGetCertPacket):
                    raise ValueError('Invalid packet type')
                return ClientPacketSerializer._serialize_get_cert(packet, format_string, flat_data)
            case _:
                return b''

    @staticmethod
    def _serialize_send(p: ClientSendPacket, format_string: str, flat_data: list[int | bytes],
                        private_key, peer_public_key) -> bytes:
        if not private_key:
            raise ValueError('Private key is required for signing')

        part1 = struct.pack(format_string, *flat_data)
        part2 = CentralizedEncryption.sign_msg(private_key, peer_public_key, p.uid, p.subject, p.body)

        return part1 + part2

    @staticmethod
    def _serialize_ask_queue(format_string: str, flat_data: list[int | bytes]) -> bytes:
        return struct.pack(format_string, *flat_data)

    @staticmethod
    def _serialize_get_msg(packet: ClientGetMSGPacket, format_string: str, flat_data: list[int | bytes]) -> bytes:
        format_string += 'I'
        flat_data.append(packet.msg_num)
        return struct.pack(format_string, *flat_data)

    @staticmethod
    def _serialize_params(p: ClientParamsPacket, format_string: str, flat_data: list[int | bytes]) -> bytes:
        len_params = len(p.params)
        flat_data.extend([len_params, p.params])
        format_string += 'H%ds' % len_params
        return struct.pack(format_string, *flat_data)

    @staticmethod
    def _serialize_public_key(p: ClientPublicKeyPacket, format_string: str, flat_data: list[int | bytes]) -> bytes:
        len_public_key = len(p.public_key)
        flat_data.extend([len_public_key, p.public_key])
        format_string += 'H%ds' % len_public_key
        return struct.pack(format_string, *flat_data)

    @staticmethod
    def _serialize_handshake(p: ClientHandshakePacket, format_string: str, flat_data: list[int | bytes]) -> bytes:
        len_signature, len_cert, len_salt = len(p.signature), len(p.cert), len(p.salt)
        flat_data.extend([len_signature, p.signature, len_cert, p.cert, len(p.salt), p.salt])
        format_string += 'H%dsH%dsB%ds' % (len_signature, len_cert, len_salt)
        return struct.pack(format_string, *flat_data)

    @staticmethod
    def _serialize_get_cert(p: ClientGetCertPacket, format_string: str, flat_data: list[int | bytes]) -> bytes:
        uid_bytes = p.uid.encode('utf-8')
        len_uid = len(uid_bytes)
        flat_data.extend([len_uid, uid_bytes])
        format_string += 'B%ds' % len_uid
        return struct.pack(format_string, *flat_data)


class ClientPacketStreamDeserializer:
    @staticmethod
    def deserialize(s: socket) -> Union[Type[Packet], Packet]:
        data = s.recv(3)
        if not data:
            raise ConnectionAbortedError('Connection closed')

        packet_type, packet_id = struct.unpack('!BH', data)
        match ClientPacketType(packet_type):
            case ClientPacketType.PARAMS:
                return ClientPacketStreamDeserializer._deserialize_params(s, packet_id)
            case ClientPacketType.PUBLIC_KEY:
                return ClientPacketStreamDeserializer._deserialize_public_key(s, packet_id)
            case ClientPacketType.HANDSHAKE:
                return ClientPacketStreamDeserializer._deserialize_handshake(s, packet_id)
            case _:
                raise ValueError('Unknown packet type | Not implemented with stream deserializer')

    @staticmethod
    def _deserialize_params(s: socket, packet_id: int) -> ClientParamsPacket:
        len_params = struct.unpack('!H', s.recv(2))[0]
        params = s.recv(len_params)
        return ClientParamsPacket(packet_id, params)

    @staticmethod
    def _deserialize_public_key(s: socket, packet_id: int) -> ClientPublicKeyPacket:
        len_public_key = struct.unpack('!H', s.recv(2))[0]
        public_key = s.recv(len_public_key)
        return ClientPublicKeyPacket(packet_id, public_key)

    @staticmethod
    def _deserialize_handshake(s: socket, packet_id: int) -> ClientHandshakePacket:
        len_signature = struct.unpack('!H', s.recv(2))[0]
        signature = s.recv(len_signature)
        len_cert = struct.unpack('!H', s.recv(2))[0]
        cert = s.recv(len_cert)
        len_salt = struct.unpack('!B', s.recv(1))[0]
        salt = s.recv(len_salt)
        return ClientHandshakePacket(packet_id, signature, cert, salt)


class ClientPacketDataDeserializer(PacketDataDeserializer):
    """
    Deserializes packets from bytes
    Used when an encrypted packet is read all at once
        -- that's why ClientPacketStreamDeserializer is not used after handshake
    """
    @staticmethod
    def deserialize(data: bytes) -> Union[Type[Packet], Packet]:
        type_and_id = data[0:3]
        if not type_and_id:
            raise ConnectionAbortedError('Connection closed')

        packet_type, packet_id = struct.unpack('!BH', type_and_id)
        match ClientPacketType(packet_type):
            case ClientPacketType.SEND:
                return ClientPacketDataDeserializer._deserialize_send(data[3:], packet_id)
            case ClientPacketType.ASK_QUEUE:
                return ClientPacketDataDeserializer._deserialize_ask_queue(packet_id)
            case ClientPacketType.GET_MSG:
                return ClientPacketDataDeserializer._deserialize_get_msg(data[3:], packet_id)
            case ClientPacketType.GET_CERT:
                return ClientPacketDataDeserializer._deserialize_get_cert(data[3:], packet_id)
            case _:
                raise ValueError('Unknown packet type | Not implemented with data deserializer')

    @staticmethod
    def _deserialize_send(data: bytes, packet_id: int) -> ClientSendPacket:
        lu = struct.unpack('!H', data[0:2])[0]
        uid = data[2:2 + lu]
        ls = struct.unpack('!H', data[2 + lu:4 + lu])[0]
        subject = data[4 + lu:4 + lu + ls]  # better not decode (encrypted)
        lb = struct.unpack('!H', data[4 + lu + ls:6 + lu + ls])[0]
        body = data[6 + lu + ls:6 + lu + ls + lb]  # better not decode (encrypted)
        lsi = struct.unpack('!H', data[6 + lu + ls + lb:8 + lu + ls + lb])[0]
        signature = data[8 + lu + ls + lb:8 + lu + ls + lb + lsi]
        lsk = struct.unpack('!H', data[8 + lu + ls + lb + lsi:10 + lu + ls + lb + lsi])[0]
        encrypted_symmetric_key = data[10 + lu + ls + lb + lsi:10 + lu + ls + lb + lsi + lsk]
        return ClientSendPacket(packet_id, uid, subject, body, signature, encrypted_symmetric_key)

    @staticmethod
    def _deserialize_ask_queue(packet_id: int) -> ClientAskQueuePacket:
        return ClientAskQueuePacket(packet_id)

    @staticmethod
    def _deserialize_get_msg(data: bytes, packet_id: int) -> ClientGetMSGPacket:
        msg_num = struct.unpack('!I', data[0:4])[0]
        return ClientGetMSGPacket(packet_id, msg_num)

    @staticmethod
    def _deserialize_get_cert(data: bytes, packet_id: int) -> ClientGetCertPacket:
        len_uid = struct.unpack('!B', data[0:1])[0]
        uid = struct.unpack('!%ds' % len_uid, data[1:1 + len_uid])[0].decode('utf-8')
        return ClientGetCertPacket(packet_id, uid)
