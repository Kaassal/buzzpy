# Import libraries
import logging
from logging.handlers import RotatingFileHandler
import socket
import threading
import paramiko

# String configurations for different modes
DEMO_STRINGS = {
    "ssh_banner": "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2-DEMO",
    "hostname": "demo-honeypot",
    "username": "demouser",
    "shell_prompt": "demouser@demo-honeypot:~$ ",
    "welcome_message": "Welcome to Demo Honeypot! For testing purposes only.",
    "shell_commands": {
        b"pwd": b"/home/demouser",
        b"whoami": b"demouser",
        b"ls": b"demo1.txt demo2.txt demo3.txt",
        b"id": b"uid=1000(demouser) gid=1000(demouser) groups=1000(demouser)",
        b"uname": b"Linux demo-honeypot 4.15.0-54-generic #58-Ubuntu SMP x86_64 GNU/Linux",
        b"hostname": b"demo-honeypot"
    }
}

REAL_STRINGS = {
    "ssh_banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
    "hostname": "ubuntu22-prod",
    "username": "sysadmin",
    "shell_prompt": "sysadmin@ubuntu22-prod:~$ ",
    "welcome_message": "Ubuntu 22.04.3 LTS\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-92-generic x86_64)\n",
    "shell_commands": {
        b"pwd": b"/home/sysadmin",
        b"whoami": b"sysadmin",
        b"ls": b"backups  configs  logs  scripts  tools",
        b"ls -l": b"total 20\ndrwxr-x--- 2 sysadmin sysadmin 4096 Apr 20 10:24 backups\ndrwxr-x--- 2 sysadmin sysadmin 4096 Apr 20 10:24 configs\ndrwxr-x--- 2 sysadmin sysadmin 4096 Apr 20 10:24 logs\ndrwxr-x--- 2 sysadmin sysadmin 4096 Apr 20 10:24 scripts\ndrwxr-x--- 2 sysadmin sysadmin 4096 Apr 20 10:24 tools",
        b"ls -la": b"total 40\ndrwx------ 6 sysadmin sysadmin 4096 Apr 20 10:24 .\ndrwxr-xr-x 4 root     root     4096 Apr 20 10:24 ..\n-rw------- 1 sysadmin sysadmin  220 Apr 20 10:24 .bash_logout\n-rw------- 1 sysadmin sysadmin 3771 Apr 20 10:24 .bashrc\n-rw------- 1 sysadmin sysadmin  807 Apr 20 10:24 .profile\ndrwxr-x--- 2 sysadmin sysadmin 4096 Apr 20 10:24 backups\ndrwxr-x--- 2 sysadmin sysadmin 4096 Apr 20 10:24 configs\ndrwxr-x--- 2 sysadmin sysadmin 4096 Apr 20 10:24 logs\ndrwxr-x--- 2 sysadmin sysadmin 4096 Apr 20 10:24 scripts\ndrwxr-x--- 2 sysadmin sysadmin 4096 Apr 20 10:24 tools",
        b"id": b"uid=1000(sysadmin) gid=1000(sysadmin) groups=1000(sysadmin),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)",
        b"groups": b"sysadmin adm cdrom sudo dip plugdev",
        b"uname": b"Linux ubuntu22-prod 5.15.0-92-generic #102-Ubuntu SMP x86_64 GNU/Linux",
        b"uname -a": b"Linux ubuntu22-prod 5.15.0-92-generic #102-Ubuntu SMP Thu Feb 15 14:24:35 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux",
        b"hostname": b"ubuntu22-prod",
        b"df": b"Filesystem     1K-blocks      Used Available Use% Mounted on\n/dev/sda1      41251136  12123084  27080668  31% /\ntmpfs            803944         0    803944   0% /dev/shm",
        b"df -h": b"Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        40G   12G   26G  31% /\ntmpfs           785M     0  785M   0% /dev/shm",
        b"free": b"              total        used        free      shared  buff/cache   available\nMem:        1607888      843012      152484        3768      612392      609108\nSwap:       2097152      124088     1973064",
        b"free -h": b"               total        used        free      shared  buff/cache   available\nMem:           1.5G        823M        148M        3.7M        597M        594M\nSwap:          2.0G        121M        1.9G",
        b"ps": b"  PID TTY          TIME CMD\n 1234 pts/0    00:00:00 bash\n 5678 pts/0    00:00:00 ps",
        b"ps aux": b"-bash: ps: Permission denied",
        b"netstat": b"Active Internet connections (w/o servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 localhost:39812         localhost:27017         ESTABLISHED\ntcp6       0      0 localhost:27017         localhost:39812         ESTABLISHED",
        b"netstat -tunlp": b"-bash: netstat: Permission denied",
        b"w": b" 13:45:03 up 42 days,  2:32,  1 user,  load average: 0.08, 0.03, 0.01\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nsysadmin pts/0    tmux(1234)       13:44    0.00s  0.04s  0.00s w",
        b"who": b"sysadmin pts/0        2024-04-25 13:44 (tmux(1234))",
        b"date": b"Thu Apr 25 13:45:04 UTC 2024",
        b"uptime": b" 13:45:03 up 42 days,  2:32,  1 user,  load average: 0.08, 0.03, 0.01",
        b"cat /etc/passwd": b"-bash: /etc/passwd: Permission denied",
        b"cat /etc/shadow": b"-bash: /etc/shadow: Permission denied",
        b"sudo": b"sudo: command not found",  # Make it look like sudo isn't installed - good bait
        b"su": b"-bash: su: Permission denied",
        b"vim": b"-bash: vim: command not found",
        b"nano": b"-bash: nano: command not found",
        b"gcc": b"-bash: gcc: command not found",
        b"perl": b"-bash: perl: command not found",
        b"python": b"-bash: python: command not found",
        b"python3": b"-bash: python3: command not found"
    }
}

# Get the appropriate string configuration
def get_strings(demo_mode=False):
    return DEMO_STRINGS if demo_mode else REAL_STRINGS

# Constant variables
LOGGING_FORMAT = logging.Formatter("%(asctime)s %(message)s")  # Added timestamp to format
SSH_BANNER = "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2"  # TODO: Add JSON for strings
HOST_KEY = paramiko.RSAKey(filename="server.key")

# Update logging to ensure proper separation of credentials and commands.
FUNNEL_LOGGER = logging.getLogger("FunnelLogger")
FUNNEL_LOGGER.setLevel(logging.INFO)
FUNNEL_HANDLER = RotatingFileHandler(
    "log_files/audits.log", maxBytes=2000, backupCount=5
)
FUNNEL_HANDLER.setFormatter(LOGGING_FORMAT)
FUNNEL_LOGGER.addHandler(FUNNEL_HANDLER)

CREDS_LOGGER = logging.getLogger("CmdLogger")
CREDS_LOGGER.setLevel(logging.INFO)
CREDS_HANDLER = RotatingFileHandler(
    "log_files/cmd_audits.log", maxBytes=2000, backupCount=5
)
CREDS_HANDLER.setFormatter(LOGGING_FORMAT)
CREDS_LOGGER.addHandler(CREDS_HANDLER)

SHELL_COMMANDS = {
    b"pwd": b"/usr/local",
    b"whoami": b"honeypotuser",
    b"ls": b"sshHoneypot.conf backup config scripts",
    b"id": b"uid=1000(honeypotuser) gid=1000(honeypotuser) groups=1000(honeypotuser)",
    b"uname": b"Linux honeypot 4.15.0-54-generic #58-Ubuntu SMP x86_64 GNU/Linux",
    b"hostname": b"honeypot-srv01",
}


def clean_command(command):
    """Clean command from escape sequences and control characters before logging"""
    if not command:
        return command
    # Remove ANSI escape sequences and control characters
    escape_chars = [b'\x1b[A', b'\x1b[B', b'\x1b[C', b'\x1b[D', b'\x08', b'\x7f']
    cleaned = command
    for esc in escape_chars:
        cleaned = cleaned.replace(esc, b'')
    return cleaned.strip()


def emulated_shell(channel, client_ip, demo_mode=False):
    """
    Emulates a restricted shell environment for the SSH honeypot.

    Args:
        channel (paramiko.Channel): The SSH channel.
        client_ip (str): The IP address of the client.
        demo_mode (bool): Whether to use demo strings or real strings.
    """
    strings = get_strings(demo_mode)
    # Send welcome message with proper line endings
    channel.send(strings["welcome_message"].replace('\n', '\r\n').encode())
    shell_prompt = strings["shell_prompt"].encode()
    channel.send(shell_prompt)
    command = b""
    command_history = []
    history_index = 0
    current_dir = b"/home/sysadmin"  # Track current directory for cd command
    
    while True:
        char = channel.recv(1)

        # Handle disconnection
        if not char:
            channel.close()
            break

        # Handle special keys
        if char == b'\x1b':  # ESC sequence
            next_char = channel.recv(1)
            if next_char == b'[':
                arrow = channel.recv(1)
                if arrow == b'A':  # Up arrow
                    if command_history and history_index < len(command_history):
                        # Clear current line
                        channel.send(b'\x1b[2K\r')
                        channel.send(shell_prompt)
                        history_index = min(history_index + 1, len(command_history))
                        command = command_history[-history_index]
                        channel.send(command)
                elif arrow == b'B':  # Down arrow
                    if history_index > 0:
                        # Clear current line
                        channel.send(b'\x1b[2K\r')
                        channel.send(shell_prompt)
                        history_index = max(history_index - 1, 0)
                        if history_index == 0:
                            command = b""
                        else:
                            command = command_history[-history_index]
                        channel.send(command)
            continue

        # Handle backspace/delete
        if char in (b'\x7f', b'\x08'):
            if command:
                command = command[:-1]
                channel.send(b'\x08 \x08')  # Move back, erase, move back
            continue

        # Handle Ctrl+C
        if char == b'\x03':
            channel.send(b'^C\r\n')
            channel.send(shell_prompt)
            command = b""
            continue

        # Handle Ctrl+D
        if char == b'\x04' and not command:
            channel.send(b'logout\r\n')
            channel.close()
            break

        # Echo character
        channel.send(char)

        # Handle enter key
        if char == b'\r':
            channel.send(b'\n')
            command = command.strip()

            # Handle empty command
            if not command:
                channel.send(shell_prompt)
                continue

            # Add command to history if non-empty
            if command and (not command_history or command != command_history[-1]):
                command_history.append(command)
            history_index = 0

            # Handle exit command
            if command == b'exit':
                channel.send(b"logout\r\nConnection closed.\r\n")
                channel.close()
                break

            # Special handling for cd command
            if command.startswith(b'cd'):
                parts = command.split(None, 1)
                if len(parts) == 1:  # just 'cd'
                    channel.send(b"-bash: cd: Permission denied\r\n")
                else:
                    channel.send(b"-bash: cd: Permission denied: " + parts[1] + b"\r\n")
                channel.send(shell_prompt)
                command = b""
                continue

            # Handle implemented commands
            shell_commands = strings["shell_commands"]
            if command in shell_commands:
                response = shell_commands[command]
                # Ensure proper line endings
                if b'\n' in response:
                    response = response.replace(b'\n', b'\r\n')
                channel.send(response + b'\r\n')
            else:
                # Handle command arguments by checking command prefix
                cmd_parts = command.split(b' ', 1)
                base_cmd = cmd_parts[0]
                
                # Check if the base command exists in our commands
                base_exists = any(cmd.split(b' ', 1)[0] == base_cmd for cmd in shell_commands.keys())
                
                if base_exists:
                    # Command exists but this variant isn't implemented
                    channel.send(b"-bash: " + base_cmd + b": Permission denied\r\n")
                else:
                    # Command doesn't exist at all
                    channel.send(b"-bash: " + base_cmd + b": command not found\r\n")

            # Log the cleaned command
            cleaned_command = clean_command(command)
            if cleaned_command:  # Only log if there's a command after cleaning
                log_command(cleaned_command, client_ip)
                
            channel.send(shell_prompt)
            command = b""
        else:
            command += char


class Server(paramiko.ServerInterface):
    """
    Implements the SSH server interface for the honeypot.
    """

    def __init__(self, client_ip, input_username=None, input_password=None, demo_mode=False):
        super().__init__()
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password
        self.strings = get_strings(demo_mode)

    def check_channel_request(self, kind, chanid):
        if (kind == "session"):
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        log_credentials(self.client_ip, username, password)

        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            return paramiko.AUTH_FAILED
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True

    def check_channel_exec_request(self, channel, command):
        return True


def client_handle(client, addr, username, password, demo_mode=False):
    """
    Handles client connections to the SSH honeypot.

    Args:
        client (socket.socket): The client socket.
        addr (tuple): The client address.
        username (str): The username for authentication.
        password (str): The password for authentication.
        demo_mode (bool): Whether to use demo strings or real strings.
    """
    client_ip = addr[0]
    print(f"{client_ip} connected to honeypot")
    strings = get_strings(demo_mode)

    try:
        transport = paramiko.Transport(client)
        transport.local_version = strings["ssh_banner"] 
        server = Server(
            client_ip=client_ip, 
            input_username=username, 
            input_password=password,
            demo_mode=demo_mode
        )

        transport.add_server_key(HOST_KEY)
        transport.start_server(server=server)
        channel = transport.accept(100)

        if channel is None:
            print("No channel was opened!")
            return

        emulated_shell(channel, client_ip=client_ip, demo_mode=demo_mode)

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


def honeypot(address, port, username, password, demo_mode=False):
    """
    Sets up the SSH honeypot server.

    Args:
        address (str): The IP address to bind.
        port (int): The port to bind.
        username (str): The username for authentication.
        password (str): The password for authentication.
        demo_mode (bool): Whether to use demo strings or real strings.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((address, port))

    server_socket.listen(50)
    mode = "DEMO MODE" if demo_mode else "PRODUCTION MODE"
    print(f"SSH honeypot listening on {address}:{port} ({mode})")

    while True:
        try:
            client, addr = server_socket.accept()
            ssh_honeypot_thread = threading.Thread(
                target=client_handle, 
                args=(client, addr, username, password),
                kwargs={"demo_mode": demo_mode}
            )
            ssh_honeypot_thread.start()
        except Exception as error:
            print(error)


# Ensure only credentials are logged to audits.log.
def log_credentials(client_ip, username, password):
    FUNNEL_LOGGER.info(
        "Client %s connection attempt username: %s, password: %s",
        client_ip,
        username,
        password,
    )


# Ensure only commands are logged to cmd_audits.log.
def log_command(command, client_ip):
    CREDS_LOGGER.info("Command: %s Client: %s", command, client_ip)
