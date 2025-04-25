# Import libraries
import logging
from logging.handlers import RotatingFileHandler
import socket
import threading
import paramiko
from datetime import datetime, timedelta
import pytz
import random
import time
import os
import json
from pathlib import Path


# Constant variables
LOGGING_FORMAT = logging.Formatter("%(asctime)s %(message)s")
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


# Store the start time of the honeypot for uptime calculations
HONEYPOT_START_TIME = time.time()


def get_uptime():
    """Generate a realistic uptime string based on honeypot runtime"""
    uptime_seconds = time.time() - HONEYPOT_START_TIME
    # Add a base uptime to make it look like the system was running before
    base_uptime = 42 * 24 * 60 * 60  # 42 days in seconds
    total_seconds = base_uptime + uptime_seconds

    days = int(total_seconds // (24 * 60 * 60))
    hours = int((total_seconds % (24 * 60 * 60)) // (60 * 60))
    minutes = int((total_seconds % (60 * 60)) // 60)

    # Get load averages (simulated with slight variations)
    load1 = round(random.uniform(0.05, 0.12), 2)
    load5 = round(random.uniform(0.02, 0.08), 2)
    load15 = round(random.uniform(0.01, 0.04), 2)

    return f" {datetime.now().strftime('%H:%M:%S')} up {days} days, {hours:02d}:{minutes:02d}, 1 user, load average: {load1}, {load5}, {load15}"


def get_ps_output(base_pid=1234):
    """Generate a realistic ps output with dynamic PIDs and timing"""
    now = datetime.now()
    random_seconds = random.randint(0, 59)
    cmd_time = f"{random_seconds:02d}:{random_seconds:02d}"

    # Generate a few realistic processes
    processes = [
        (base_pid, "pts/0", cmd_time, "bash"),
        (base_pid + 1, "pts/0", "00:00", "sshd"),
        (base_pid + random.randint(2, 100), "pts/0", "00:00", "ps"),
    ]

    output = b"  PID TTY          TIME CMD\n" + b"\n".join(
        f"{pid:5d} {tty:8} {time:>8} {cmd}".encode()
        for pid, tty, time, cmd in processes
    )
    return output


def get_who_output():
    """Generate a realistic who/w output with current time"""
    now = datetime.now()
    login_time = now.strftime("%H:%M")
    idle_mins = random.randint(0, 5)
    idle_time = f"{idle_mins:02d}:{random.randint(0, 59):02d}"
    return f"sysadmin pts/0        {now.strftime('%Y-%m-%d')} {login_time} ({idle_time})".encode()


def load_honeypot_strings(demo_mode=False):
    """Load honeypot strings from JSON configuration file"""
    config_path = Path(__file__).parent / "config" / "ssh_honeypot_strings.json"
    try:
        with open(config_path, "r") as f:
            strings = json.load(f)
            mode = "demo" if demo_mode else "real"
            config = strings[mode]

            # Convert shell command values to bytes
            config["shell_commands"] = {
                k.encode(): v.encode() for k, v in config["shell_commands"].items()
            }
            return config
    except Exception as e:
        print(f"Error loading honeypot strings: {e}")
        return None


# Get the appropriate string configuration
def get_strings(demo_mode=False):
    return load_honeypot_strings(demo_mode)


def clean_command(command):
    """Clean command from escape sequences and control characters before logging"""
    if not command:
        return command
    # Remove ANSI escape sequences and control characters
    escape_chars = [b"\x1b[A", b"\x1b[B", b"\x1b[C", b"\x1b[D", b"\x08", b"\x7f"]
    cleaned = command
    for esc in escape_chars:
        cleaned = cleaned.replace(esc, b"")
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
    channel.send(strings["welcome_message"].replace("\n", "\r\n").encode())
    shell_prompt = strings["shell_prompt"].encode()
    channel.send(shell_prompt)
    command = b""
    command_history = []
    history_index = 0

    while True:
        char = channel.recv(1)

        # Handle disconnection
        if not char:
            channel.close()
            break

        # Handle special keys
        if char == b"\x1b":  # ESC sequence
            next_char = channel.recv(1)
            if next_char == b"[":
                arrow = channel.recv(1)
                if arrow == b"A":  # Up arrow
                    if command_history and history_index < len(command_history):
                        # Clear current line
                        channel.send(b"\x1b[2K\r")
                        channel.send(shell_prompt)
                        history_index = min(history_index + 1, len(command_history))
                        command = command_history[-history_index]
                        channel.send(command)
                elif arrow == b"B":  # Down arrow
                    if history_index > 0:
                        # Clear current line
                        channel.send(b"\x1b[2K\r")
                        channel.send(shell_prompt)
                        history_index = max(history_index - 1, 0)
                        if history_index == 0:
                            command = b""
                        else:
                            command = command_history[-history_index]
                        channel.send(command)
            continue

        # Handle backspace/delete
        if char in (b"\x7f", b"\x08"):
            if command:
                command = command[:-1]
                channel.send(b"\x08 \x08")  # Move back, erase, move back
            continue

        # Handle Ctrl+C
        if char == b"\x03":
            channel.send(b"^C\r\n")
            channel.send(shell_prompt)
            command = b""
            continue

        # Handle Ctrl+D
        if char == b"\x04" and not command:
            channel.send(b"logout\r\n")
            channel.close()
            break

        # Echo character
        channel.send(char)

        # Handle enter key
        if char == b"\r":
            channel.send(b"\n")
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
            if command == b"exit":
                channel.send(b"logout\r\nConnection closed.\r\n")
                channel.close()
                break

            # Special handling for cd command
            if command.startswith(b"cd"):
                parts = command.split(None, 1)
                if len(parts) == 1:  # just 'cd'
                    channel.send(b"-bash: cd: Permission denied\r\n")
                else:
                    channel.send(b"-bash: cd: Permission denied: " + parts[1] + b"\r\n")
                channel.send(shell_prompt)
                command = b""
                continue

            # Handle dynamic commands first
            if command == b"date":
                current_time = datetime.now(pytz.UTC)
                date_str = current_time.strftime("%a %b %d %H:%M:%S UTC %Y").encode()
                channel.send(date_str + b"\r\n")
            elif command == b"ps" or command == b"ps aux" or command == b"ps -ef":
                if command == b"ps":
                    channel.send(get_ps_output() + b"\r\n")
                else:
                    channel.send(b"-bash: ps: Permission denied\r\n")
            elif command == b"w" or command == b"who":
                channel.send(get_who_output() + b"\r\n")
            elif command == b"uptime":
                channel.send(get_uptime().encode() + b"\r\n")
            elif command == b"free" or command == b"free -h":
                channel.send(b"-bash: free: Permission denied\r\n")
            elif command.startswith(b"cat "):
                # Extract the file path from the cat command
                file_path = command[4:].strip()  # Remove 'cat ' and any whitespace
                if file_path == b"/etc/hosts":
                    response = strings["shell_commands"][command]
                    channel.send(response.replace(b"\n", b"\r\n") + b"\r\n")
                elif file_path == b"/etc/":
                    channel.send(b"-bash: cat: /etc/: Is a directory\r\n")
                else:
                    channel.send(b"-bash: cat: Permission denied\r\n")
            elif command == b"cat":
                channel.send(
                    b"-bash: cat: missing operand\nTry 'cat --help' for more information.\r\n"
                )
            elif command in strings["shell_commands"]:
                response = strings["shell_commands"][command]
                # Ensure proper line endings
                if b"\n" in response:
                    response = response.replace(b"\n", b"\r\n")
                channel.send(response + b"\r\n")
            else:
                # Handle command arguments by checking command prefix
                cmd_parts = command.split(b" ", 1)
                base_cmd = cmd_parts[0]

                # Check if the base command exists in our commands
                base_exists = any(
                    cmd.split(b" ", 1)[0] == base_cmd
                    for cmd in strings["shell_commands"].keys()
                )

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

    def __init__(
        self, client_ip, input_username=None, input_password=None, demo_mode=False
    ):
        super().__init__()
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password
        self.strings = get_strings(demo_mode)

    def check_channel_request(self, kind, chanid):
        if kind == "session":
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
            demo_mode=demo_mode,
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
                kwargs={"demo_mode": demo_mode},
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
