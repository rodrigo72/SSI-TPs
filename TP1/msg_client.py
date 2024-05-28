import re
import socket
import sys
import traceback
import os

from datetime import datetime
from re import Match
from threading import Thread, Lock
from queue import Queue, Empty
from typing import Dict
from enum import IntEnum

from utils import (get_p12_data, read_file_as_bytes, HandshakeInfo, get_agreed_kdf, validate_cert,
                   get_pseudonym_from_certificate)

from packets import *

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509 import Certificate
from cryptography.fernet import Fernet

MAX_SUBJECT_LENGTH = 200
MAX_BODY_LENGTH = 1000
USERDATA_FILE = 'userdata.p12'
PARAMS_FILE = 'params.pem'
DEBUG = False


class Client:
    def __init__(
            self,
            private_key_rsa,
            cert,
            ca_cert,
            server_address: str = '127.0.0.1',
            server_port: int = 8443,
            timeout: int = 60 * 10,
            debug: bool = False
    ):
        self.private_key_rsa = private_key_rsa
        self.cert = cert
        self.ca_cert = ca_cert
        self.handshake_info = None
        self.pseudonym = get_pseudonym_from_certificate(cert)

        self.server_address = server_address
        self.server_port = server_port
        self.timeout = timeout
        self.debug = debug
        self.socket = None
        self.done = False
        self.next_id = 0
        self.lock = Lock()
        self.responses: Dict[str, Queue] = {
            'queue_elements': Queue(),
            'queue_info': Queue(),
            'msg': Queue(),
            'cert': Queue()
        }

    def get_next_id(self) -> int:
        self.next_id += 1
        return self.next_id

    def print(self, message: str) -> None:
        if self.debug:
            print('>> ', datetime.now(), message)

    def stop(self) -> None:
        self.done = True

        if self.socket:
            self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.close()
            self.socket = None

    def connect_to_server(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.server_address, self.server_port))
        self.socket.settimeout(self.timeout)

    def handshake_aux(self, client: socket, address, packet_type) -> Packet | None:
        func_name = self.handshake_aux.__name__
        try:
            p = ServerPacketStreamDeserializer.deserialize(client)
        except ValueError as error:
            self.print(f'[{func_name}] Error deserializing data from {address}: {error}')
            p = None

        if not p or p.type != packet_type:
            self.print(f'[{func_name}] Invalid packet')
            return None

        return p

    def custom_validate_cert(self, cert: Certificate) -> bool:
        return validate_cert(
            cert,
            self.ca_cert,
            [
                (x509.NameOID.ORGANIZATIONAL_UNIT_NAME, 'SSI MSG RELAY SERVICE'),
                (x509.NameOID.PSEUDONYM, 'MSG_SERVER')
            ],
            [(x509.ExtensionOID.BASIC_CONSTRAINTS, lambda ext: not ext.ca),
             (x509.ExtensionOID.KEY_USAGE, lambda ext: ext.digital_signature or ext.non_repudiation)]
        )

    def handshake(self) -> HandshakeInfo | None:
        func_name = self.handshake.__name__
        info = HandshakeInfo()
        try:
            # get params
            func_name = self.handshake.__name__
            params_bytes = read_file_as_bytes(PARAMS_FILE)
            info.params = serialization.load_pem_parameters(
                params_bytes,
                backend=default_backend()
            )

            # send params
            params_packet = ClientParamsPacket(self.get_next_id(), params_bytes)
            self.socket.sendall(ClientPacketSerializer.serialize(params_packet))

            # receive response
            p = self.handshake_aux(self.socket, self.server_address, ServerPacketType.STATUS)
            if (p is None
                    or not isinstance(p, ServerStatusResponsePacket)
                    or p.status != ServerStatusResponsePacket.Status.OK):
                return None

            # generate dl keys
            info.private_key_dl = info.params.generate_private_key()
            info.public_key_dl = info.private_key_dl.public_key()
            info.public_key_dl_pem = info.public_key_dl.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # send public key
            public_key_packet = ClientPublicKeyPacket(self.get_next_id(), info.public_key_dl_pem)
            self.socket.sendall(ClientPacketSerializer.serialize(public_key_packet))

            # receive server public key, signature, cert
            p = self.handshake_aux(self.socket, self.server_address, ServerPacketType.HANDSHAKE)
            if p is None or not isinstance(p, ServerHandshakePacket):
                return None

            server_public_key_bytes = p.public_key

            # validate certificate
            server_cert = x509.load_pem_x509_certificate(p.cert, backend=default_backend())
            if not self.custom_validate_cert(server_cert):
                self.print('Invalid client certificate')
                return None

            # validate signature
            message = server_public_key_bytes + info.public_key_dl_pem
            if not CentralizedEncryption.verify_signature(server_cert.public_key(), p.signature, message):
                self.print(f'[{func_name}] Invalid signature')
                return None

            # send signature, cert and salt
            salt = os.urandom(16)
            message = info.public_key_dl_pem + server_public_key_bytes + salt
            signature = CentralizedEncryption.sign_bytes(self.private_key_rsa, message)

            cert_bytes = self.cert.public_bytes(serialization.Encoding.PEM)
            handshake_packet = ClientHandshakePacket(self.get_next_id(), signature, cert_bytes, salt)
            self.socket.sendall(ClientPacketSerializer.serialize(handshake_packet))

            server_public_key = serialization.load_pem_public_key(server_public_key_bytes)
            info.shared_key = info.private_key_dl.exchange(server_public_key)

            kdf = get_agreed_kdf(salt)
            key = kdf.derive(info.shared_key)
            info.aes_key = key[:32]
            info.hmac_key = key[32:]

            return info
        except Exception as error:
            self.print(f'[{func_name}] Error during handshake: {error}')
            return None

    def run(self) -> None:
        func_name = self.run.__name__
        try:
            if not self.socket:
                self.connect_to_server()

            if self.handshake_info is None:
                self.handshake_info = self.handshake()
                if self.handshake_info is None:
                    self.stop()
                    return

            while not self.done:
                try:
                    p = EncryptedPacketDeserializer.deserialize(
                        self.socket, self.handshake_info.aes_key, self.handshake_info.hmac_key,
                        ServerPacketDataDeserializer)
                except ValueError as error:
                    self.print(f'[{func_name}] Error deserializing data: {error}')
                    continue

                match p.type:
                    case ServerPacketType.QUEUE_ELEMENT:
                        self.responses['queue_elements'].put_nowait(p)
                    case ServerPacketType.QUEUE_INFO:
                        self.responses['queue_info'].put_nowait(p)
                    case ServerPacketType.MSG:
                        self.responses['msg'].put_nowait(p)
                    case ServerPacketType.SEND_CERT:
                        self.responses['cert'].put_nowait(p)
                    case _:
                        self.print('Unknown packet type')

        except socket.timeout:
            self.print(f'[{func_name}] Socket timeout')
        except ConnectionAbortedError as error:
            self.print(f'[{func_name}] Connection closed: {error}')
        except Exception as error:
            self.print(f'[{func_name}] Error: {error}')
            self.print(traceback.format_exc())
        finally:
            self.stop()

    def send_msg_packet(self, peer_public_key, send_to: str, subject: str, body: str) -> None:
        p = ClientSendPacket(self.get_next_id(), send_to, subject, body)
        self.socket.sendall(
            EncryptedPacketSerializer.serialize(
                p, self.handshake_info.aes_key, self.handshake_info.hmac_key, ClientPacketSerializer,
                private_key=self.private_key_rsa,
                public_key=peer_public_key
            )
        )

    def send_ask_queue_packet(self) -> None:
        p = ClientAskQueuePacket(self.get_next_id())
        self.send_encrypted_packet(p)

    def send_get_msg_packet(self, msg_num: int) -> None:
        p = ClientGetMSGPacket(self.get_next_id(), msg_num)
        self.send_encrypted_packet(p)

    def send_encrypted_packet(self, p: Packet) -> None:
        self.socket.sendall(
            EncryptedPacketSerializer.serialize(
                p, self.handshake_info.aes_key, self.handshake_info.hmac_key, ClientPacketSerializer
            )
        )

    def send_get_cert_packet(self, pseudonym: str) -> None:
        p = ClientGetCertPacket(self.get_next_id(), pseudonym)
        self.send_encrypted_packet(p)


class ClientController:
    def __init__(
            self,
            msg_client: Client,
    ) -> None:
        self.client = msg_client
        self.done = False
        self.commands = [
            (re.compile(rf'^ *send +(\w+) +"(.{{1,{MAX_SUBJECT_LENGTH}}}?)" +"(.{{1,{MAX_BODY_LENGTH}}}?)" *$'), self.send_aux_func),
            (re.compile(r'(?i)^exit$'), lambda _: (setattr(self, 'done', True), self.client.stop())),
            (re.compile(r'(?i)^askqueue$'), lambda _: self.get_queue_elements(self.client)),
            (re.compile(r'(?i)^getmsg +(\d+)$'), self.get_msg_aux_func)
        ]

    def run(self) -> None:
        while not self.done and not self.client.done:
            try:
                command = input('> ').strip()
                if self.done:
                    break
                self.parse_command(command)
            except KeyboardInterrupt:
                self.done = True
                self.client.stop()
            except Exception as error:
                self.client.print(f'[ClientController - run] Error: {error}')
                self.client.print(traceback.format_exc())

    def parse_command(self, command: str):
        for regex, func in self.commands:
            if match := regex.match(command):
                func(match)
                return
        print('MSG RELAY SERVICE: command error!', file=sys.stderr)

    def send_aux_func(self, match: Match[str], timeout: int = 3) -> None:
        send_to, subject, body = match.groups()
        self.send_msg(self.client, send_to, subject, body, timeout)

    @staticmethod
    def send_msg(client: Client, send_to: str, subject: str, body: str, timeout: int = 3):
        if ClientController.check_lengths(subject, body):
            client.send_get_cert_packet(send_to)
            try:
                p = client.responses['cert'].get(timeout=timeout, block=True)
            except Empty:
                print('MSG RELAY SERVICE: Timeout waiting for response', file=sys.stderr)
                return

            if p.status == ServerSendCertPacket.Status.NOT_FOUND:
                print('MSG RELAY SERVICE: unknown user!', file=sys.stderr)
                return

            result = validate_cert(p.cert, client.ca_cert, [
                (x509.NameOID.ORGANIZATIONAL_UNIT_NAME, 'SSI MSG RELAY SERVICE'),
                (x509.NameOID.PSEUDONYM, send_to)
            ], [
                (x509.ExtensionOID.BASIC_CONSTRAINTS, lambda ext: not ext.ca),
                (x509.ExtensionOID.KEY_USAGE, lambda ext: ext.digital_signature or ext.non_repudiation)
            ])

            if not result:
                print('MSG RELAY SERVICE: verification error!', file=sys.stderr)
                return
            client.send_msg_packet(p.cert.public_key(), send_to, subject, body)
        else:
            print('MSG RELAY SERVICE: command error!', file=sys.stderr)

    def get_msg_aux_func(self, match: Match[str]) -> None:
        msg_num = match.group(1)
        self.client.send_get_msg_packet(int(msg_num))
        ClientController.get_asked_msg(self.client)

    @staticmethod
    def get_asked_msg(client: Client, timeout: int = 3) -> None:
        try:
            p: ServerMSGPacket = client.responses['msg'].get(timeout=timeout, block=True)
            if p.status == ServerMSGPacket.Status.NOT_FOUND:
                print('MSG RELAY SERVICE: unknown message!', file=sys.stderr)
            elif p.status == ServerMSGPacket.Status.OK_NO_CERT:
                print('MSG RELAY SERVICE: verification error!', file=sys.stderr)
            elif p.status == ServerMSGPacket.Status.OK:
                sent_to = client.pseudonym.encode('utf-8')
                sent_by = p.sent_by.decode('utf-8')

                result = validate_cert(p.cert, client.ca_cert, [
                       (x509.NameOID.ORGANIZATIONAL_UNIT_NAME, 'SSI MSG RELAY SERVICE'),
                       (x509.NameOID.PSEUDONYM, sent_by)
                   ], [
                       (x509.ExtensionOID.BASIC_CONSTRAINTS, lambda ext: not ext.ca),
                       (x509.ExtensionOID.KEY_USAGE, lambda ext: ext.digital_signature or ext.non_repudiation)
                   ])

                if not result:
                    print('invalid certificate')
                    print('MSG RELAY SERVICE: verification error!', file=sys.stderr)
                    return

                result = CentralizedEncryption.verify_signed_msg(
                    p.cert.public_key(),
                    client.private_key_rsa,
                    sent_to, p.subject, p.body,
                    p.signature,
                    p.encrypted_symmetric_key
                )

                if result is None:
                    print('invalid signature')
                    print('MSG RELAY SERVICE: verification error!', file=sys.stderr)
                    return

                datetime_obj = datetime.fromtimestamp(p.timestamp)
                print(f'{sent_by}:{datetime_obj}:{result[0].decode("utf-8")}:{result[1].decode("utf-8")}')
        except Empty:
            client.print('Timeout waiting for response')

    @staticmethod
    def check_lengths(subject: str, body: str) -> bool:
        if len(subject.encode('utf-8')) > MAX_SUBJECT_LENGTH:
            print(f'Subject is too long. Max length is {MAX_SUBJECT_LENGTH} bytes.')
            return False
        elif len(body.encode('utf-8')) > MAX_BODY_LENGTH:
            print(f'Body is too long. Max length is {MAX_BODY_LENGTH} bytes.')
            return False
        return True

    @staticmethod
    def get_queue_elements(client: Client, timeout_info: int = 3, timeout_element: int = 3) -> None:
        client.send_ask_queue_packet()
        queue_info: ServerQueueInfoPacket = client.responses['queue_info'].get(timeout=timeout_info, block=True)
        if queue_info.state == ServerQueueInfoPacket.State.EMPTY:
            return

        count = 0
        queue_elements = []
        while count < queue_info.num_elements:
            try:
                e: ServerQueueElementPacket = client.responses['queue_elements'].get(timeout=timeout_element, block=True)
                datetime_obj = datetime.fromtimestamp(e.timestamp)

                try:
                    key = CentralizedEncryption.decrypt_bytes(client.private_key_rsa, e.encrypted_symmetric_key)
                    f = Fernet(key)
                    dec_sub = f.decrypt(e.subject).decode('utf-8')
                    queue_elements.append(f'{e.num}:{e.sender_uid.decode("utf-8")}:{datetime_obj}:{dec_sub}')
                except Exception as e:
                    client.print(f'Error decrypting subject: {e}')
                    print('MSG RELAY SERVICE: verification error!', file=sys.stderr)

                count += 1
            except Empty:
                client.print('Timeout waiting for response')
                break

        print('\n'.join(queue_elements))


def main(argv: list[str]) -> None:
    class Command:
        class Type(IntEnum):
            SEND = 1
            ASK_QUEUE = 2
            GET_MSG = 3

        def __init__(self, command_type: Type, args: list[str]):
            self.command_type = command_type
            self.args = args

    help_str = """Usage:
    msg_client.py [-user <filename>] send <uid> <subject>
    msg_client.py [-user <filename>] askqueue
    msg_client.py [-user <filename>] getmsg <num>
    msg_client.py [-user <filename>] help"""

    p = 0
    filename = USERDATA_FILE
    if len(argv) > 2 and argv[1] == '-user':
        p = 2
        filename = argv[2]

    try:
        private_key, user_cert, ca_cert = get_p12_data(filename)
    except Exception as e:
        print(f'Error loading user data: {e}', file=sys.stderr)
        sys.exit(1)

    c = None

    if len(argv) > 3 + p and argv[1 + p] == 'send':
        send_to = argv[2 + p]
        subject = argv[3 + p]
        body = sys.stdin.read()
        c = Command(Command.Type.SEND, [send_to, subject, body])
    elif len(argv) > 1 + p and argv[1 + p] == 'askqueue':
        c = Command(Command.Type.ASK_QUEUE, [])
    elif len(argv) > 2 + p and argv[1 + p] == 'getmsg':
        msg_num = argv[2 + p]
        c = Command(Command.Type.GET_MSG, [msg_num])
    elif len(argv) > 1 + p and argv[1 + p] == 'help':
        print(help_str)
        sys.exit(0)
    elif len(argv) > 1 + p:
        print('MSG RELAY SERVICE: command error!', file=sys.stderr)
        print(help_str, file=sys.stderr)
        sys.exit(1)

    client = Client(private_key, user_cert, ca_cert, debug=DEBUG)
    client.connect_to_server()
    info = client.handshake()

    if info is None:
        print('Handshake failed')
        sys.exit(1)
    else:
        client.handshake_info = info

    try:
        client_thread = Thread(target=client.run)
        client_thread.start()

        if c is not None:
            match c.command_type:
                case Command.Type.SEND:
                    ClientController.send_msg(client, c.args[0], c.args[1], c.args[2])
                case Command.Type.ASK_QUEUE:
                    try:
                        ClientController.get_queue_elements(client)
                    except Exception as error:
                        client.print(f'Error getting queue elements: {error}')
                case Command.Type.GET_MSG:
                    try:
                        msg_num = int(c.args[0])
                    except ValueError:
                        print('MSG RELAY SERVICE: command error!', file=sys.stderr)
                        sys.exit(1)
                    client.send_get_msg_packet(msg_num)
                    ClientController.get_asked_msg(client, timeout=5)
                case _:
                    print('MSG RELAY SERVICE: command error!', file=sys.stderr)

            client.stop()
            client_thread.join()
        else:
            controller = ClientController(client)
            controller.run()

    except KeyboardInterrupt:
        print('Shutting down client ...')
        client.stop()
        sys.exit(0)
    except Exception as e:
        client.print(f'[main] Error: {e}')
        sys.exit(1)


if __name__ == '__main__':
    main(sys.argv)
