#Everlyline with this comment "Change this" can and should be changed
#if you want people to interact with the honeypot

#Import libraries
import logging
from logging.handlers import RotatingFileHandler
import socket
import paramiko
import socket
import threading

#Constant vars
logging_format = logging.Formatter('%(message)s')
#The banner can be changed,it is just a string, a vulneable version has been selected to lure auditors and/or attackers 
SSH_BANNER = "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2 honeypot" #Change this (delete honeypot)
host_key = paramiko.RSAKey(filename ='server.key')

#Logging
funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('audits.log',maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger('FunnelLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('cmd_audits.log',maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)

#Shell emulation

def emulated_shell(channel, client_ip):
    channel.send(b'ssh-honeypot$ ')
    command = b""
    while True:
        char = channel.recv(1)
        channel.send(char)
        if not char:
            channel.close()

        command += char
        #TODO: Find a more elegant way of doing data collection
        if char == b'\r':
            if command.strip() == b'exit':
                response = b'\n Connection terminated \n'
                channel.close() 
            elif command.strip() == b'pwd':
                response = b"\n" + b'\\usr\\local' + b'\r\n'
                creds_logger.info(f'Command {command.strip()} ' + ' Client: ' + f'{client_ip}')
            elif command.strip() == b'whoami':
                response = b"\n" + b"honeypotUser1" + b"\r\n" #Change this
                creds_logger.info(f'Command {command.strip()} ' + ' Client: ' + f'{client_ip}')
            elif command.strip() == b'ls':
                response = b'\n' + b"sshHoneypot.conf" + b"\r\n" # Change this
                creds_logger.info(f'Command {command.strip()} ' + ' Client: ' + f'{client_ip}')
            elif command.strip() == b'cat Honeypot.conf': # Change this
                response = b'\n' + b"cat placeholder" + b"\r\n"
                creds_logger.info(f'Command {command.strip()} ' + ' Client: ' + f'{client_ip}')
            else:
                response = b"\n" + bytes(command.strip()) + b"\r\n"
                creds_logger.info(f'Command {command.strip()} ' + ' Client: ' + f'{client_ip}')
            channel.send(response)
            channel.send(b'ssh-honeypot$ ')
            command = b""

# SSH Server and Sockets

class Server (paramiko.ServerInterface):

    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        
    def get_allowed_auths(self, username):
        return "password"
    
    def check_auth_password(self, username, password):
        funnel_logger.info(f'Client {self.client_ip} connection attempt' + f'username: {username},' + f'password: {password}')
        creds_logger.info(f'{self.client_ip},{username},{password}')
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED

        else: 
            return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True
    
    def check_channel_exec_request(self, channel, command):
        command = str(command)
        return True
    
def client_handle (client, addr, username ,password):
    client_ip = addr[0]
    print(f"{client_ip} connected to honeypot")

    try:
            
            transport = paramiko.Transport(client)
            transport.local_version = SSH_BANNER # TODO: Custom banner likely an user enum vulnerable version of ssh
            server = Server(client_ip=client_ip, input_username=username, input_password=password)

            transport.add_server_key(host_key)
            transport.start_server(server=server)
            channel = transport.accept(100)
            if channel is None:
                print("No channel was opened!")
            
            standard_banner = "Connection succesful! Welcome to the Honeypot!" # Change this
            channel.send(standard_banner)
            emulated_shell(channel, client_ip=client_ip)
    
    except AttributeError as error:
            print (error)
            print("Error: Atribute error") # TODO: better/more verbose error messages
    finally:
        try:
            transport.close()
        except Exception as error:
            print(error)
            print("Error: Could not close connection!")
        client.close()
            
        
# SSH-based honeypot provisions

def honeypot(address,port,username,password):

    sockets = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sockets.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sockets.bind((address,port))

    sockets.listen(50) #Number of connetions, anything over 100 is unstable
    print(f"SSH server listening, port: {port}")

    while True:
        try:
            client , addr = sockets.accept()
            ssh_honeypot_thread = threading.Thread(target=client_handle, args=(client, addr, username, password))
            ssh_honeypot_thread.start()
        except Exception as error:
            print (error)

honeypot('127.0.0.1', 2222, username=None, password=None)