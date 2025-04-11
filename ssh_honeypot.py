# Import libraries
import logging
from logging.handlers import RotatingFileHandler
import socket
import threading
import paramiko

# Constant variables
LOGGING_FORMAT = logging.Formatter('%(message)s')
SSH_BANNER = "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2"  # Updated to remove 'honeypot'
HOST_KEY = paramiko.RSAKey(filename='server.key')

# Logging setup for audit and command logs
FUNNEL_LOGGER = logging.getLogger('FunnelLogger')
FUNNEL_LOGGER.setLevel(logging.INFO)
FUNNEL_HANDLER = RotatingFileHandler('audits.log', maxBytes=2000, backupCount=5)
FUNNEL_HANDLER.setFormatter(LOGGING_FORMAT)
FUNNEL_LOGGER.addHandler(FUNNEL_HANDLER)

CREDS_LOGGER = logging.getLogger('CmdLogger')
CREDS_LOGGER.setLevel(logging.INFO)
CREDS_HANDLER = RotatingFileHandler('cmd_audits.log', maxBytes=2000, backupCount=5)
CREDS_HANDLER.setFormatter(LOGGING_FORMAT)
CREDS_LOGGER.addHandler(CREDS_HANDLER)

def emulated_shell(channel, client_ip):
    """
    Emulates a shell environment for the SSH honeypot.

    Args:
        channel (paramiko.Channel): The SSH channel.
        client_ip (str): The IP address of the client.
    """
    channel.send(b'ssh-honeypot$ ')
    command = b""
    while True:
        char = channel.recv(1)
        channel.send(char)
        if not char:
            channel.close()
            break

        command += char
        if char == b'\r':
            command = command.strip()
            if command == b'exit':
                response = b'\nConnection terminated\n'
                channel.send(response)
                channel.close()
                break
            elif command == b'pwd':
                response = b"\n/usr/local\r\n"
            elif command == b'whoami':
                response = b"\nhoneypotUser1\r\n"
            elif command == b'ls':
                response = b'\nsshHoneypot.conf\r\n'
            elif command == b'cat Honeypot.conf':
                response = b'\ncat placeholder\r\n'
            else:
                response = b"\n" + command + b"\r\n"

            CREDS_LOGGER.info('Command: %s Client: %s', command, client_ip)
            channel.send(response)
            channel.send(b'ssh-honeypot$ ')
            command = b""

class Server(paramiko.ServerInterface):
    """
    Implements the SSH server interface for the honeypot.
    """

    def __init__(self, client_ip, input_username=None, input_password=None):
        super().__init__()
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        FUNNEL_LOGGER.info(
            'Client %s connection attempt username: %s, password: %s',
            self.client_ip, username, password
        )
        CREDS_LOGGER.info('%s,%s,%s', self.client_ip, username, password)

        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            return paramiko.AUTH_FAILED
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        return True

def client_handle(client, addr, username, password):
    """
    Handles client connections to the SSH honeypot.

    Args:
        client (socket.socket): The client socket.
        addr (tuple): The client address.
        username (str): The username for authentication.
        password (str): The password for authentication.
    """
    client_ip = addr[0]
    print(f"{client_ip} connected to honeypot")

    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = Server(client_ip=client_ip, input_username=username, input_password=password)

        transport.add_server_key(HOST_KEY)
        transport.start_server(server=server)
        channel = transport.accept(100)

        if channel is None:
            print("No channel was opened!")
            return

        welcome_message = "Connection successful! Welcome to the Honeypot!"
        channel.send(welcome_message.encode())
        emulated_shell(channel, client_ip=client_ip)

    except AttributeError as error:
        print(error)
        print("Error: Attribute error")
    finally:
        try:
            transport.close()
        except Exception as error:
            print(error)
            print("Error: Could not close connection!")
        client.close()

def honeypot(address, port, username, password):
    """
    Sets up the SSH honeypot server.

    Args:
        address (str): The IP address to bind.
        port (int): The port to bind.
        username (str): The username for authentication.
        password (str): The password for authentication.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((address, port))

    server_socket.listen(50)
    print(f"SSH server listening on port: {port}")

    while True:
        try:
            client, addr = server_socket.accept()
            ssh_honeypot_thread = threading.Thread(
                target=client_handle, args=(client, addr, username, password)
            )
            ssh_honeypot_thread.start()
        except Exception as error:
            print(error)