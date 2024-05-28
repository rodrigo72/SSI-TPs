import argparse
import socket
import sys
import time
import traceback

from argparse import Namespace
from collections import defaultdict
from datetime import datetime
from threading import Thread, Lock
from typing import Dict

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509 import Certificate

from utils import (get_p12_data, HandshakeInfo, get_pseudonym_from_certificate, validate_cert, get_agreed_kdf)
from packets import *


class Message:
    def __init__(self, num: int, subject: bytes, body: bytes, timestamp: int, send_to: bytes,
                 signature: bytes, sent_by: bytes, encrypted_symmetric_key) -> None:
        self.num = num
        self.send_to = send_to
        self.subject = subject
        self.body = body
        self.timestamp = timestamp
        self.signature = signature
        self.sent_by = sent_by
        self.encrypted_symmetric_key = encrypted_symmetric_key

    def __str__(self) -> str:
        return f'Num: {self.num}, Sender: {self.send_to}, Subject: {self.subject}, Timestamp: {self.timestamp}'


class ClientMessages:
    def __init__(self) -> None:
        self.read_msgs: Dict[int, Message] = {}
        self.unread_msgs: Dict[int, Message] = {}
        self.next_id: int = 0

    def add_unread_msg(self, subject: bytes, body: bytes, timestamp: int, sender: bytes,
                       signature: bytes, sent_by: bytes, encrypted_symmetric_key: bytes) -> None:
        self.unread_msgs[self.next_id] = Message(
            self.next_id, subject, body, timestamp, sender, signature, sent_by, encrypted_symmetric_key
        )
        self.next_id += 1

    def read_unread_msg(self, num: int) -> Message | None:
        msg = self.unread_msgs.get(num, None)
        if msg is not None:
            self.read_msgs[num] = msg
            del self.unread_msgs[num]
            return msg

        return self.read_msgs.get(num, None)

    def __str__(self) -> str:
        read_str = ', '.join(str(msg) for msg in self.read_msgs)
        unread_str = ', '.join(str(msg) for msg in self.unread_msgs)
        return f'Read messages: [{read_str}]\nUnread messages: [{unread_str}]'


class Server:
    def __init__(
            self,
            private_key_rsa,
            cert: Certificate,
            ca_cert: Certificate,
            port: int = 8443,
            address: str = '127.0.0.1',
            max_connections: int = 5,
            timeout: int = 60 * 10,
            debug: bool = False
    ) -> None:
        self.private_key_rsa = private_key_rsa
        self.cert = cert
        self.ca_cert = ca_cert

        self.socket = None
        self.port = port
        self.address = address
        self.max_connections = max_connections
        self.timeout = timeout
        self.debug = debug
        self.threads = []
        self.done = False
        self.lock = Lock()
        self.msgs: Dict[str, ClientMessages] = defaultdict(ClientMessages)
        self.next_id = 0
        self.certificates: Dict[str, Certificate] = {}

    def print(self, message: str) -> None:
        if self.debug:
            print('>> ', datetime.now(), message)

    def get_next_id(self) -> int:
        self.next_id += 1
        return self.next_id

    def run(self) -> None:
        self.print('Starting server ...')

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.address, self.port))
        self.print(f'Server listening on {self.address}:{self.port}')

        self.socket.listen(self.max_connections)
        self.print(f'Max connections: {self.max_connections}')

        while not self.done:
            try:
                client, address = self.socket.accept()
                client.settimeout(self.timeout)
                self.print(f'Accepted connection from {address}')

                thread = Thread(target=self.listen_to_client, args=(client, address))
                self.threads.append(thread)
                thread.start()
            except socket.timeout:
                self.print('[run] Socket timeout')
                break
            except socket.error as error:
                self.print(f'[run] Error accepting connection: {error}')
                break

    def stop(self) -> None:
        self.done = True
        for thread in self.threads:
            thread.join()

    def handshake_aux(self, client: socket, address, packet_type) -> Packet | None:
        func_name = self.handshake_aux.__name__
        try:
            p = ClientPacketStreamDeserializer.deserialize(client)
        except ValueError as error:
            self.print(f'[{func_name}] Error deserializing data from {address}: {error}')
            p = None

        if not p or p.type != packet_type:
            self.print(f'[{func_name}] Invalid packet')
            client.sendall(ServerPacketSerializer.serialize(
                ServerStatusResponsePacket(self.get_next_id(), ServerStatusResponsePacket.Status.ERROR)))
            return None

        return p

    def custom_validate_cert(self, cert: Certificate) -> bool:
        return validate_cert(
            cert,
            self.ca_cert,
            [(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, 'SSI MSG RELAY SERVICE')],
            [(x509.ExtensionOID.BASIC_CONSTRAINTS, lambda ext: not ext.ca),
             (x509.ExtensionOID.KEY_USAGE, lambda ext: ext.digital_signature or ext.non_repudiation)]
        )

    def handshake(self, client: socket, address) -> HandshakeInfo | None:
        info = HandshakeInfo()
        try:
            # receive parameters
            params_packet = self.handshake_aux(client, address, ClientPacketType.PARAMS)
            if params_packet is None or not isinstance(params_packet, ClientParamsPacket):
                return None

            client.sendall(ServerPacketSerializer.serialize(
                ServerStatusResponsePacket(self.get_next_id(), ServerStatusResponsePacket.Status.OK)))

            params_bytes = params_packet.params
            info.params = serialization.load_pem_parameters(
                params_bytes,
                backend=default_backend()
            )

            # generate dl keys
            info.private_key_dl = info.params.generate_private_key()
            info.public_key_dl = info.private_key_dl.public_key()
            info.public_key_dl_pem = info.public_key_dl.public_bytes(
               encoding=serialization.Encoding.PEM,
               format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # receive client public key
            pubkey_packet = self.handshake_aux(client, address, ClientPacketType.PUBLIC_KEY)
            if pubkey_packet is None or not isinstance(pubkey_packet, ClientPublicKeyPacket):
                return None

            client_public_key_bytes = pubkey_packet.public_key

            # send public key, signature, cert
            message = info.public_key_dl_pem + client_public_key_bytes
            signature = CentralizedEncryption.sign_bytes(self.private_key_rsa, message)

            cert_bytes = self.cert.public_bytes(serialization.Encoding.PEM)
            handshake_packet = ServerHandshakePacket(self.get_next_id(), info.public_key_dl_pem, signature, cert_bytes)
            client.sendall(ServerPacketSerializer.serialize(handshake_packet))

            # receive  sig, cert, salt
            handshake_packet = self.handshake_aux(client, address, ClientPacketType.HANDSHAKE)
            if handshake_packet is None or not isinstance(handshake_packet, ClientHandshakePacket):
                return None

            salt = handshake_packet.salt

            # validate cert
            client_cert = x509.load_pem_x509_certificate(handshake_packet.cert, default_backend())
            if not self.custom_validate_cert(client_cert):
                self.print('Invalid client certificate')
                return None

            # get client pseudonym
            client_pseudonym = get_pseudonym_from_certificate(client_cert)
            if client_pseudonym is None:
                self.print('Invalid client pseudonym')
                return None

            info.peer_pseudonym = client_pseudonym
            self.certificates[client_pseudonym] = client_cert

            # verify signature
            client_public_key_rsa = client_cert.public_key()
            message = client_public_key_bytes + info.public_key_dl_pem + salt
            if not CentralizedEncryption.verify_signature(client_public_key_rsa, handshake_packet.signature, message):
                self.print('Invalid signature')
                return None

            # compute shared key
            client_public_key = serialization.load_pem_public_key(client_public_key_bytes)
            info.shared_key = info.private_key_dl.exchange(client_public_key)

            kdf = get_agreed_kdf(salt)
            key = kdf.derive(info.shared_key)
            info.aes_key = key[:32]
            info.hmac_key = key[32:]

            return info
        except Exception as error:
            self.print(f'Error during handshake: {error}')
            self.print(traceback.format_exc())
            return None

    def listen_to_client(self, client: socket, address) -> None:
        leave = False

        info = self.handshake(client, address)
        if info is None:
            client.close()
            return

        while not leave:
            try:
                self.print(f'Waiting for data from {info.peer_pseudonym}')
                try:
                    p = (EncryptedPacketDeserializer
                         .deserialize(client, info.aes_key, info.hmac_key, ClientPacketDataDeserializer))
                except ValueError as error:
                    self.print(f'[listen_to_client] Error deserializing data from {address}: {error}')
                    self.print(traceback.format_exc())
                    continue

                self.print(f'Received data from {address}:\n{p.type}')

                match p.type:
                    case ClientPacketType.SEND:
                        self.handle_send(p, info.peer_pseudonym)
                    case ClientPacketType.ASK_QUEUE:
                        self.handle_ask_queue(client, info.peer_pseudonym, info)
                    case ClientPacketType.GET_MSG:
                        self.handle_get_msg(client, p, info.peer_pseudonym, info)
                    case ClientPacketType.GET_CERT:
                        self.handle_get_cert(client, p, info)
                    case _:
                        self.print(f'Unknown packet type: {p.type}')

            except ConnectionAbortedError as error:
                self.print(f'[listen_to_client] {error}')
                break
            except Exception as error:
                self.print(f'[listen_to_client] Error receiving data from {address}: {error}')
                self.print(traceback.format_exc())
                break

    def handle_send(self, p: ClientSendPacket, client_uid: str):
        timestamp = int(time.time())
        sent_by = client_uid.encode('utf-8')
        send_to = p.uid.decode('utf-8') if isinstance(p.uid, bytes) else p.uid
        with self.lock:
            client_msgs = self.msgs[send_to]
            client_msgs.add_unread_msg(p.subject, p.body, timestamp, p.uid, p.signature, sent_by,
                                       p.encrypted_symmetric_key)

    def handle_ask_queue(self, client: socket, client_uid: str, info: HandshakeInfo):
        with self.lock:
            client_msgs = self.msgs[client_uid]
            unread_msgs = client_msgs.unread_msgs.values()

        n_id = self.get_next_id()
        if len(unread_msgs) == 0:
            q_info = ServerQueueInfoPacket(n_id, ServerQueueInfoPacket.State.EMPTY)
        else:
            q_info = ServerQueueInfoPacket(n_id, ServerQueueInfoPacket.State.NOT_EMPTY, num_elements=len(unread_msgs))

        Server.send_encrypted_packet(client, q_info, info)

        if len(unread_msgs) != 0:
            for m in unread_msgs:
                elem_packet = ServerQueueElementPacket(self.get_next_id(), m.num, m.send_to, m.timestamp, m.subject,
                                                       m.encrypted_symmetric_key)
                Server.send_encrypted_packet(client, elem_packet, info)

    def handle_get_msg(self, client, pac: ClientGetMSGPacket, client_uid: str, info: HandshakeInfo):
        with self.lock:
            client_msgs = self.msgs[client_uid]
            m: Message = client_msgs.read_unread_msg(pac.msg_num)

        nid = self.get_next_id()
        if m is None:
            p = ServerMSGPacket(nid, ServerMSGPacket.Status.NOT_FOUND)
        else:
            cert = self.certificates.get(m.sent_by.decode('utf-8'), None)
            if cert is None:
                p = ServerMSGPacket(
                    nid, ServerMSGPacket.Status.OK_NO_CERT, m.sent_by, m.timestamp, m.subject, m.body, m.signature)
            else:
                p = ServerMSGPacket(
                    nid, ServerMSGPacket.Status.OK, m.sent_by, m.timestamp, m.subject, m.body, m.signature, cert,
                    m.encrypted_symmetric_key)
        Server.send_encrypted_packet(client, p, info)

    def handle_get_cert(self, client: socket, pac: ClientGetCertPacket, info: HandshakeInfo):
        cert = self.certificates.get(pac.uid, None)
        if cert is None:
            p = ServerSendCertPacket(self.get_next_id(), ServerSendCertPacket.Status.NOT_FOUND)
        else:
            p = ServerSendCertPacket(self.get_next_id(), ServerSendCertPacket.Status.OK, cert)
        Server.send_encrypted_packet(client, p, info)

    @staticmethod
    def send_encrypted_packet(client: socket, p: Packet, info: HandshakeInfo) -> None:
        client.sendall(
            EncryptedPacketSerializer.serialize(p, info.aes_key, info.hmac_key, ServerPacketSerializer)
        )


def parse_args() -> Namespace | None:
    try:
        parser = argparse.ArgumentParser(description='MSG Server Command Line Options')
        parser.add_argument('-p', '--port', type=int, default=8443, help='Port to bind the server to')
        parser.add_argument('-d', '--debug', default=False, action='store_true', help='Enable debug mode')
        parser.add_argument('-m', '--max', type=int, default=5, help='Maximum number of connections')
        parser.add_argument('-t', '--timeout', type=int, default=60 * 10, help='Timeout for connections')
        parser.add_argument('-D', '--data', type=str, default='serverdata.p12', help='Server data file path')

        return parser.parse_args()
    except argparse.ArgumentError as error:
        print(f'Error parsing command line arguments: {error}')
        return None


def main():
    args = parse_args()
    if args is None:
        sys.exit(1)

    private_key, cert, ca_cert = get_p12_data(args.data)
    server = Server(private_key, cert, ca_cert, port=args.port, debug=args.debug, max_connections=args.max,
                    timeout=args.timeout)

    try:
        server.run()
    except KeyboardInterrupt:
        print('Shutting down server ...')
        server.stop()
        sys.exit(0)
    except Exception as e:
        print(f'Error: {e}')
        server.stop()
        sys.exit(1)


if __name__ == '__main__':
    main()
