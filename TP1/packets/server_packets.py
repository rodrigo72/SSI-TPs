import socket
import struct

from packets import PacketType, Packet, PacketSerializer, PacketDataDeserializer
from enum import IntEnum
from typing import Type, Union
from cryptography.x509 import Certificate, load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class ServerPacketType(PacketType):
    QUEUE_INFO = 0
    QUEUE_ELEMENT = 1
    MSG = 2
    STATUS = 3
    HANDSHAKE = 4
    SEND_CERT = 5

    def __str__(self) -> str:
        return self.name


class ServerStatusResponsePacket(Packet):
    class Status(IntEnum):
        OK = 0
        ERROR = 1

    def __init__(self, packet_id: int, status: Status) -> None:
        super().__init__(packet_id, ServerPacketType.STATUS)
        self.status = status


class ServerHandshakePacket(Packet):
    def __init__(self, packet_id: int, public_key: bytes, signature: bytes, cert: bytes) -> None:
        super().__init__(packet_id, ServerPacketType.HANDSHAKE)
        self.public_key = public_key
        self.signature = signature
        self.cert = cert


class ServerQueueInfoPacket(Packet):
    class State(IntEnum):
        EMPTY = 0
        NOT_EMPTY = 1

    def __init__(self, packet_id: int, state: State, num_elements: int = None) -> None:
        super().__init__(packet_id, ServerPacketType.QUEUE_INFO)
        self.state = state
        self.num_elements = num_elements

    def __str__(self) -> str:
        return f'{super().__str__()}, State: {self.state}, Num elements: {self.num_elements}'


class ServerQueueElementPacket(Packet):
    def __init__(self, packet_id: int, num: int, sender: bytes, timestamp: int, subject: bytes,
                 encrypted_symmetric_key: bytes) -> None:
        super().__init__(packet_id, ServerPacketType.QUEUE_ELEMENT)
        self.num = num
        self.sender_uid = sender
        self.timestamp = timestamp
        self.subject = subject
        self.encrypted_symmetric_key = encrypted_symmetric_key

    def __str__(self) -> str:
        return f'{super().__str__()}, Num: {self.num}, Sender: {self.sender_uid}, Timestamp: {self.timestamp}, \
        Subject: {self.subject}'


class ServerMSGPacket(Packet):
    class Status(IntEnum):
        OK = 0
        NOT_FOUND = 1
        OK_NO_CERT = 2

    def __init__(self, packet_id: int, status: Status, sent_by: bytes = None, timestamp: int = None,
                 subject: bytes = None, body: bytes = None, signature: bytes = None, cert: Certificate = None,
                 encrypted_symmetric_key: bytes = None) -> None:
        super().__init__(packet_id, ServerPacketType.MSG)
        self.status = status
        self.sent_by = sent_by
        self.timestamp = timestamp
        self.subject = subject
        self.body = body
        self.signature = signature
        self.cert = cert
        self.encrypted_symmetric_key = encrypted_symmetric_key

    def __str__(self) -> str:
        return f'{super().__str__()}, Status: {self.status}, Sender: {self.sent_by}, Timestamp: {self.timestamp}, \
        Subject: {self.subject}, Body: {self.body}'


class ServerSendCertPacket(Packet):
    class Status(IntEnum):
        OK = 0
        NOT_FOUND = 1

    def __init__(self, packet_id: int, status: Status, cert: Certificate = None) -> None:
        super().__init__(packet_id, ServerPacketType.SEND_CERT)
        self.status = status
        self.cert = cert


class ServerPacketSerializer(PacketSerializer):
    @staticmethod
    def serialize(packet: Packet, private_key=None, public_key=None) -> bytes:
        format_string = '!BH'
        flat_data = [packet.type.value, packet.id]

        match packet.type:
            case ServerPacketType.QUEUE_ELEMENT:
                if not isinstance(packet, ServerQueueElementPacket):
                    raise ValueError('Invalid packet type')
                return ServerPacketSerializer._serialize_queue_elem(packet, format_string, flat_data)
            case ServerPacketType.QUEUE_INFO:
                if not isinstance(packet, ServerQueueInfoPacket):
                    raise ValueError('Invalid packet type')
                return ServerPacketSerializer._serialize_queue_info(packet, format_string, flat_data)
            case ServerPacketType.MSG:
                if not isinstance(packet, ServerMSGPacket):
                    raise ValueError('Invalid packet type')
                return ServerPacketSerializer._serialize_msg(packet, format_string, flat_data)
            case ServerPacketType.STATUS:
                if not isinstance(packet, ServerStatusResponsePacket):
                    raise ValueError('Invalid packet type')
                return ServerPacketSerializer._serialize_status_response(packet, format_string, flat_data)
            case ServerPacketType.HANDSHAKE:
                if not isinstance(packet, ServerHandshakePacket):
                    raise ValueError('Invalid packet type')
                return ServerPacketSerializer._serialize_handshake(packet, format_string, flat_data)
            case ServerPacketType.SEND_CERT:
                if not isinstance(packet, ServerSendCertPacket):
                    raise ValueError('Invalid packet type')
                return ServerPacketSerializer._serialize_send_cert(packet, format_string, flat_data)
            case _:
                raise ValueError('Unknown packet type')

    @staticmethod
    def _serialize_queue_info(packet: ServerQueueInfoPacket, format_string: str, flat_data: list[int | bytes]) -> bytes:
        if packet.state == ServerQueueInfoPacket.State.EMPTY:
            format_string += 'B'
            flat_data.append(packet.state.value)
            return struct.pack(format_string, *flat_data)
        else:
            format_string += 'BI'
            flat_data.extend([packet.state.value, packet.num_elements])
            return struct.pack(format_string, *flat_data)

    @staticmethod
    def _serialize_queue_elem(p: ServerQueueElementPacket, format_string: str, flat_data: list[int | bytes]) -> bytes:
        ls, lu, lks = len(p.subject), len(p.sender_uid), len(p.encrypted_symmetric_key)
        flat_data.extend([p.num, lu, p.sender_uid, p.timestamp, ls, p.subject, lks, p.encrypted_symmetric_key])
        format_string += 'IB%dsIH%dsH%ds' % (lu, ls, lks)
        return struct.pack(format_string, *flat_data)

    @staticmethod
    def _serialize_msg(p: ServerMSGPacket, format_string: str, flat_data: list[int | bytes]) -> bytes:
        format_string += 'B'
        flat_data.append(p.status.value)

        if p.status == ServerMSGPacket.Status.OK:
            cert_bytes = p.cert.public_bytes(serialization.Encoding.PEM)
            lu, ls, lb, lsi, lc = len(p.sent_by), len(p.subject), len(p.body), len(p.signature), len(cert_bytes)
            lks = len(p.encrypted_symmetric_key)
            format_string += 'IB%dsH%dsH%dsH%dsH%dsH%ds' % (lu, ls, lb, lsi, lc, lks)
            flat_data.extend([
                p.timestamp, lu, p.sent_by, ls, p.subject, lb, p.body, lsi, p.signature, lc, cert_bytes,
                lks, p.encrypted_symmetric_key
            ])
            return struct.pack(format_string, *flat_data)
        else:
            return struct.pack(format_string, *flat_data)

    @staticmethod
    def _serialize_status_response(packet: ServerStatusResponsePacket, f_str: str, data: list[int | bytes]) -> bytes:
        f_str += 'B'
        data.append(packet.status.value)
        return struct.pack(f_str, *data)

    @staticmethod
    def _serialize_handshake(packet: ServerHandshakePacket, format_string: str, flat_data: list[int | bytes]) -> bytes:
        len_public_key, len_signature, len_cert = len(packet.public_key), len(packet.signature), len(packet.cert)
        flat_data.extend([len_public_key, packet.public_key, len_signature, packet.signature, len_cert, packet.cert])
        format_string += 'H%dsH%dsH%ds' % (len_public_key, len_signature, len_cert)
        return struct.pack(format_string, *flat_data)

    @staticmethod
    def _serialize_send_cert(packet: ServerSendCertPacket, format_string: str, flat_data: list[int | bytes]) -> bytes:
        format_string += 'B'
        flat_data.append(packet.status.value)
        if packet.status == ServerSendCertPacket.Status.OK:
            cert_bytes = packet.cert.public_bytes(serialization.Encoding.PEM)
            len_cert = len(cert_bytes)
            format_string += 'H%ds' % len_cert
            flat_data.extend([len_cert, cert_bytes])
        return struct.pack(format_string, *flat_data)


class ServerPacketStreamDeserializer:
    @staticmethod
    def deserialize(s: socket) -> Union[Type[Packet], Packet]:
        data = s.recv(3)
        if not data:
            raise ConnectionAbortedError('Connection closed')

        packet_type, packet_id = struct.unpack('!BH', data)
        match ServerPacketType(packet_type):
            case ServerPacketType.STATUS:
                return ServerPacketStreamDeserializer._deserialize_status_response(s, packet_id)
            case ServerPacketType.HANDSHAKE:
                return ServerPacketStreamDeserializer._deserialize_handshake(s, packet_id)
            case _:
                raise ValueError('Unknown packet type')

    @staticmethod
    def _deserialize_status_response(s: socket, packet_id: int) -> ServerStatusResponsePacket:
        status = struct.unpack('!B', s.recv(1))[0]
        return ServerStatusResponsePacket(packet_id, ServerStatusResponsePacket.Status(status))

    @staticmethod
    def _deserialize_handshake(s: socket, packet_id: int) -> ServerHandshakePacket:
        len_public_key = struct.unpack('!H', s.recv(2))[0]
        public_key = s.recv(len_public_key)
        len_signature = struct.unpack('!H', s.recv(2))[0]
        signature = s.recv(len_signature)
        len_cert = struct.unpack('!H', s.recv(2))[0]
        cert = s.recv(len_cert)
        return ServerHandshakePacket(packet_id, public_key, signature, cert)


class ServerPacketDataDeserializer(PacketDataDeserializer):
    @staticmethod
    def deserialize(data: bytes) -> Union[Type[Packet], Packet]:
        type_and_id = data[:3]
        if not type_and_id:
            raise ConnectionAbortedError('Connection closed')

        packet_type, packet_id = struct.unpack('!BH', type_and_id)
        match ServerPacketType(packet_type):
            case ServerPacketType.QUEUE_ELEMENT:
                return ServerPacketDataDeserializer._deserialize_queue_element(data[3:], packet_id)
            case ServerPacketType.QUEUE_INFO:
                return ServerPacketDataDeserializer._deserialize_queue_info(data[3:], packet_id)
            case ServerPacketType.MSG:
                return ServerPacketDataDeserializer._deserialize_msg(data[3:], packet_id)
            case ServerPacketType.STATUS:
                return ServerPacketDataDeserializer._deserialize_status_response(data[3:], packet_id)
            case ServerPacketType.SEND_CERT:
                return ServerPacketDataDeserializer._deserialize_send_cert(data[3:], packet_id)
            case _:
                raise ValueError('Unknown packet type')

    @staticmethod
    def _deserialize_queue_info(data: bytes, packet_id: int) -> ServerQueueInfoPacket:
        state = struct.unpack('!B', data[:1])[0]
        if state == ServerQueueInfoPacket.State.EMPTY:
            return ServerQueueInfoPacket(packet_id, ServerQueueInfoPacket.State.EMPTY)
        else:
            num_elements = struct.unpack('!I', data[1:5])[0]
            return ServerQueueInfoPacket(packet_id, ServerQueueInfoPacket.State.NOT_EMPTY, num_elements=num_elements)

    @staticmethod
    def _deserialize_queue_element(data: bytes, packet_id: int) -> ServerQueueElementPacket:
        num, lu = struct.unpack('!IB', data[:5])
        uid = data[5:5+lu]
        timestamp = struct.unpack('!I', data[5 + lu:5 + lu + 4])[0]
        ls = struct.unpack('!H', data[5 + lu + 4: 5 + lu + 4 + 2])[0]
        subject = data[5 + lu + 4 + 2:5 + lu + 4 + 2 + ls]
        lks = struct.unpack('!H', data[5 + lu + 4 + 2 + ls:5 + lu + 4 + 2 + ls + 2])[0]
        encrypted_symmetric_key = data[5 + lu + 4 + 2 + ls + 2:5 + lu + 4 + 2 + ls + 2 + lks]
        return ServerQueueElementPacket(packet_id, num, uid, timestamp, subject, encrypted_symmetric_key)

    @staticmethod
    def _deserialize_msg(data: bytes, packet_id: int) -> ServerMSGPacket:
        status = struct.unpack('!B', data[0:1])[0]
        if status != ServerMSGPacket.Status.NOT_FOUND:
            timestamp, lu = struct.unpack('!IB', data[1:6])
            sent_by = data[6:lu+6]
            ls = struct.unpack('!H', data[lu+6:lu+8])[0]
            subject = data[lu+8:lu+ls+8]
            lb = struct.unpack('!H', data[lu+ls+8:lu+ls+10])[0]
            body = data[lu+ls+10:lu+ls+lb+10]
            lsi = struct.unpack('!H', data[lu+ls+lb+10:lu+ls+lb+12])[0]
            sig = data[lu+ls+lb+12:lu+ls+lb+lsi+12]

            if status == ServerMSGPacket.Status.OK_NO_CERT:
                return ServerMSGPacket(packet_id, ServerMSGPacket.Status(status), sent_by, timestamp, subject, body, sig)

            lc = struct.unpack('!H', data[lu+ls+lb+lsi+12:lu+ls+lb+lsi+14])[0]
            c = load_pem_x509_certificate(data[lu+ls+lb+lsi+14:lu+ls+lb+lsi+lc+14], default_backend())
            lks = struct.unpack('!H', data[lu+ls+lb+lsi+lc+14:lu+ls+lb+lsi+lc+16])[0]
            encrypted_symmetric_key = data[lu+ls+lb+lsi+lc+16:lu+ls+lb+lsi+lc+lks+16]
            return ServerMSGPacket(packet_id, ServerMSGPacket.Status(status), sent_by, timestamp, subject, body, sig, c,
                                   encrypted_symmetric_key)
        else:
            return ServerMSGPacket(packet_id, ServerMSGPacket.Status.NOT_FOUND)

    @staticmethod
    def _deserialize_status_response(data: bytes, packet_id: int) -> ServerStatusResponsePacket:
        status = struct.unpack('!B', data[0:1])[0]
        return ServerStatusResponsePacket(packet_id, ServerStatusResponsePacket.Status(status))

    @staticmethod
    def _deserialize_send_cert(data: bytes, packet_id: int) -> ServerSendCertPacket:
        status = struct.unpack('!B', data[0:1])[0]
        if status == ServerSendCertPacket.Status.OK:
            len_cert = struct.unpack('!H', data[1:3])[0]
            cert = load_pem_x509_certificate(data[3:3+len_cert], default_backend())
            return ServerSendCertPacket(packet_id, ServerSendCertPacket.Status(status), cert)
        else:
            return ServerSendCertPacket(packet_id, ServerSendCertPacket.Status(status))
