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


def get_memory_stats():
    """Generate slightly varying memory statistics"""
    # Base values
    total_mem = 1607888
    total_swap = 2097152

    # Generate varying used memory (around 50-55%)
    used_mem = int(total_mem * (random.uniform(0.50, 0.55)))
    buff_cache = int(total_mem * (random.uniform(0.35, 0.40)))
    free_mem = total_mem - used_mem - buff_cache

    # Generate varying swap usage (around 5-7%)
    used_swap = int(total_swap * (random.uniform(0.05, 0.07)))
    free_swap = total_swap - used_swap

    # Format for both normal and -h output
    normal = (
        b"              total        used        free      shared  buff/cache   available\n"
        b"Mem:        %8d %10d %9d %9d %10d %10d\n"
        b"Swap:       %8d %10d %9d"
        % (
            total_mem,
            used_mem,
            free_mem,
            random.randint(3500, 4000),
            buff_cache,
            buff_cache + free_mem,
            total_swap,
            used_swap,
            free_swap,
        )
    )

    human = (
        b"               total        used        free      shared  buff/cache   available\n"
        b"Mem:           %.1fG      %.1fG      %.1fG      %d.%dM       %.1fG      %.1fG\n"
        b"Swap:          %.1fG      %.1fG      %.1fG"
        % (
            total_mem / 1024 / 1024,
            used_mem / 1024 / 1024,
            free_mem / 1024 / 1024,
            random.randint(3, 4),
            random.randint(5, 9),
            buff_cache / 1024 / 1024,
            (buff_cache + free_mem) / 1024 / 1024,
            total_swap / 1024 / 1024,
            used_swap / 1024 / 1024,
            free_swap / 1024 / 1024,
        )
    )

    return normal, human


def get_disk_stats():
    """Generate slightly varying disk usage statistics"""
    # Base values
    total_space = 41251136
    data_space = 5242880

    # Generate varying usage (system disk 29-32%, data disk 88-92%)
    sys_used = int(total_space * (random.uniform(0.29, 0.32)))
    sys_avail = total_space - sys_used

    data_used = int(data_space * (random.uniform(0.88, 0.92)))
    data_avail = data_space - data_used

    # Format for both normal and -h output
    normal = (
        b"Filesystem     1K-blocks      Used Available Use% Mounted on\n"
        b"/dev/sda1      %9d %9d %9d %3d%% /\n"
        b"tmpfs            803944         0    803944   0%% /dev/shm\n"
        b"/dev/sdb1       %7d %9d %8d %3d%% /data"
        % (
            total_space,
            sys_used,
            sys_avail,
            sys_used * 100 // total_space,
            data_space,
            data_used,
            data_avail,
            data_used * 100 // data_space,
        )
    )

    human = (
        b"Filesystem      Size  Used Avail Use%% Mounted on\n"
        b"/dev/sda1        40G  %.1fG  %.1fG  %3d%% /\n"
        b"tmpfs           785M     0  785M   0%% /dev/shm\n"
        b"/dev/sdb1         5G  %.1fG  %.1fG  %3d%% /data"
        % (
            sys_used / 1024 / 1024,
            sys_avail / 1024 / 1024,
            sys_used * 100 // total_space,
            data_used / 1024 / 1024,
            data_avail / 1024 / 1024,
            data_used * 100 // data_space,
        )
    )

    return normal, human


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
        b"hostname": b"demo-honeypot",
    },
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
        b"ls": b"backups  configs  logs  scripts  tools  .ssh  .bash_history  .mongodb  .viminfo",
        b"ls -l": b"total 52\n"
        b"drwxr-x--- 2 sysadmin sysadmin 4096 Apr 20 10:24 backups\n"
        b"drwxr-x--- 2 sysadmin sysadmin 4096 Apr 20 10:24 configs\n"
        b"drwxr-x--- 2 sysadmin sysadmin 4096 Apr 20 10:24 logs\n"
        b"drwxr-x--- 2 sysadmin sysadmin 4096 Apr 20 10:24 scripts\n"
        b"drwxr-x--- 2 sysadmin sysadmin 4096 Apr 20 10:24 tools\n"
        b"drwx------ 2 sysadmin sysadmin 4096 Apr 20 10:24 .ssh\n"
        b"-rw------- 1 sysadmin sysadmin 8192 Apr 25 13:40 .bash_history\n"
        b"drwxr-x--- 3 sysadmin mongodb 4096 Apr 20 10:24 .mongodb\n"
        b"-rw------- 1 sysadmin sysadmin 1024 Apr 20 10:24 .viminfo",
        b"ls -la": b"total 72\n"
        b"drwx------ 6 sysadmin sysadmin 4096 Apr 20 10:24 .\n"
        b"drwxr-xr-x 4 root     root     4096 Apr 20 10:24 ..\n"
        b"-rw------- 1 sysadmin sysadmin 8192 Apr 25 13:40 .bash_history\n"
        b"-rw------- 1 sysadmin sysadmin  220 Apr 20 10:24 .bash_logout\n"
        b"-rw------- 1 sysadmin sysadmin 3771 Apr 20 10:24 .bashrc\n"
        b"drwxr-x--- 3 sysadmin mongodb 4096 Apr 20 10:24 .mongodb\n"
        b"-rw------- 1 sysadmin sysadmin  807 Apr 20 10:24 .profile\n"
        b"drwx------ 2 sysadmin sysadmin 4096 Apr 20 10:24 .ssh\n"
        b"-rw------- 1 sysadmin sysadmin 1024 Apr 20 10:24 .viminfo\n"
        b"drwxr-x--- 2 sysadmin sysadmin 4096 Apr 20 10:24 backups\n"
        b"drwxr-x--- 2 sysadmin sysadmin 4096 Apr 20 10:24 configs\n"
        b"drwxr-x--- 2 sysadmin sysadmin 4096 Apr 20 10:24 logs\n"
        b"drwxr-x--- 2 sysadmin sysadmin 4096 Apr 20 10:24 scripts\n"
        b"drwxr-x--- 2 sysadmin sysadmin 4096 Apr 20 10:24 tools",
        b"ls backups": b"-bash: ls: Permission denied",
        b"ls configs": b"-bash: ls: Permission denied",
        b"ls logs": b"-bash: ls: Permission denied",
        b"ls scripts": b"-bash: ls: Permission denied",
        b"ls tools": b"-bash: ls: Permission denied",
        b"ls .mongodb": b"mongod.conf  keyfile  admin.json",
        b"cat .mongodb/mongod.conf": b"-bash: cat: Permission denied",
        b"cat .mongodb/keyfile": b"-bash: cat: Permission denied",
        b"cat .mongodb/admin.json": b"-bash: cat: Permission denied",
        b"ls .ssh": b"authorized_keys  id_rsa  id_rsa.pub  known_hosts",
        b"cat .ssh/id_rsa": b"-bash: cat: Permission denied",
        b"cat .ssh/authorized_keys": b"-bash: cat: Permission denied",
        b"id": b"uid=1000(sysadmin) gid=1000(sysadmin) groups=1000(sysadmin),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),118(mongodb)",
        b"groups": b"sysadmin adm cdrom sudo dip plugdev mongodb",
        b"uname": b"Linux ubuntu22-prod 5.15.0-92-generic #102-Ubuntu SMP x86_64 GNU/Linux",
        b"uname -a": b"Linux ubuntu22-prod 5.15.0-92-generic #102-Ubuntu SMP Thu Feb 15 14:24:35 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux",
        b"uname -r": b"5.15.0-92-generic",
        b"hostname": b"ubuntu22-prod",
        b"df": b"Filesystem     1K-blocks      Used Available Use% Mounted on\n"
        b"/dev/sda1      41251136  12123084  27080668  31% /\n"
        b"tmpfs            803944         0    803944   0% /dev/shm\n"
        b"/dev/sdb1       5242880   4718592    524288  90% /data",
        b"df -h": b"Filesystem      Size  Used Avail Use% Mounted on\n"
        b"/dev/sda1        40G   12G   26G  31% /\n"
        b"tmpfs           785M     0  785M   0% /dev/shm\n"
        b"/dev/sdb1         5G   4.5G   512M  90% /data",
        b"free": b"              total        used        free      shared  buff/cache   available\nMem:        1607888      843012      152484        3768      612392      609108\nSwap:       2097152      124088     1973064",
        b"free -h": b"               total        used        free      shared  buff/cache   available\nMem:           1.5G        823M        148M        3.7M        597M        594M\nSwap:          2.0G        121M        1.9G",
        b"ps": b"  PID TTY          TIME CMD\n 1234 pts/0    00:00:00 bash\n 5678 pts/0    00:00:00 ps",
        b"ps aux": b"-bash: ps: Permission denied",
        b"ps -ef": b"-bash: ps: Permission denied",
        b"top": b"-bash: top: Permission denied",
        b"htop": b"-bash: htop: command not found",
        b"netstat": b"Active Internet connections (w/o servers)\n"
        b"Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
        b"tcp        0      0 localhost:39812         localhost:27017         ESTABLISHED\n"
        b"tcp6       0      0 localhost:27017         localhost:39812         ESTABLISHED\n"
        b"tcp        0      0 localhost:27017         localhost:39814         ESTABLISHED\n"
        b"tcp6       0      0 localhost:39814         localhost:27017         ESTABLISHED",
        b"netstat -tunlp": b"-bash: netstat: Permission denied",
        b"ss": b"-bash: ss: Permission denied",
        b"lsof": b"-bash: lsof: Permission denied",
        b"w": b" 13:45:03 up 42 days,  2:32,  1 user,  load average: 0.08, 0.03, 0.01\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nsysadmin pts/0    tmux(1234)       13:44    0.00s  0.04s  0.00s w",
        b"who": b"sysadmin pts/0        2024-04-25 13:44 (tmux(1234))",
        b"date": b"Thu Apr 25 13:45:04 UTC 2024",
        b"uptime": b" 13:45:03 up 42 days,  2:32,  1 user,  load average: 0.08, 0.03, 0.01",
        b"cat /etc/passwd": b"-bash: /etc/passwd: Permission denied",
        b"cat /etc/shadow": b"-bash: /etc/shadow: Permission denied",
        b"cat /etc/hosts": b"127.0.0.1 localhost\n"
        b"127.0.1.1 ubuntu22-prod\n"
        b"\n"
        b"# MongoDB replica set members\n"
        b"127.0.0.1 mongodb0.internal\n"
        b"127.0.0.1 mongodb1.internal\n"
        b"127.0.0.1 mongodb2.internal",
        b"sudo": b"sudo: command not found",
        b"su": b"-bash: su: Permission denied",
        b"vim": b"-bash: vim: command not found",
        b"nano": b"-bash: nano: command not found",
        b"gcc": b"-bash: gcc: command not found",
        b"perl": b"-bash: perl: command not found",
        b"python": b"-bash: python: command not found",
        b"python3": b"-bash: python3: command not found",
        b"mongo": b"-bash: mongo: Permission denied",
        b"mongodb": b"-bash: mongodb: Permission denied",
        b"mongosh": b"-bash: mongosh: Permission denied",
        b"mysql": b"-bash: mysql: command not found",
        b"find": b"-bash: find: Permission denied",
        b"locate": b"-bash: locate: command not found",
        b"whereis": b"-bash: whereis: Permission denied",
        b"which": b"-bash: which: Permission denied",
        b"curl": b"-bash: curl: Permission denied",
        b"wget": b"-bash: wget: Permission denied",
        b"nmap": b"-bash: nmap: command not found",
        b"nc": b"-bash: nc: Permission denied",
        b"netcat": b"-bash: netcat: Permission denied",
        b"chown": b"-bash: chown: Permission denied",
        b"chmod": b"-bash: chmod: Permission denied",
        b"mount": b"-bash: mount: Permission denied",
        b"umount": b"-bash: umount: Permission denied",
        b"cat .bash_history": b"-bash: cat: Permission denied",
        b"history": b"-bash: history: Permission denied",
        b"env": b"SHELL=/bin/bash\n"
        b"PWD=/home/sysadmin\n"
        b"LOGNAME=sysadmin\n"
        b"HOME=/home/sysadmin\n"
        b"LANG=en_US.UTF-8\n"
        b"TERM=xterm\n"
        b"USER=sysadmin\n"
        b"SHLVL=1\n"
        b"PATH=/usr/local/bin:/usr/bin:/bin\n"
        b"MAIL=/var/mail/sysadmin\n"
        b"_=/usr/bin/env",
        b"cat /proc/version": b"Linux version 5.15.0-92-generic (buildd@lcy02-amd64-017) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #102-Ubuntu SMP Thu Feb 15 14:24:35 UTC 2024",
        b"lsb_release": b"-bash: lsb_release: command not found",
        b"service": b"-bash: service: command not found",
        b"systemctl": b"-bash: systemctl: Permission denied",
        b"journalctl": b"-bash: journalctl: Permission denied",
        b"crontab": b"-bash: crontab: Permission denied",
        b"ssh-keygen": b"-bash: ssh-keygen: Permission denied",
    },
}


# Get the appropriate string configuration
def get_strings(demo_mode=False):
    return DEMO_STRINGS if demo_mode else REAL_STRINGS


# Constant variables
LOGGING_FORMAT = logging.Formatter(
    "%(asctime)s %(message)s"
)  # Added timestamp to format
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
                # Change free command to permission denied since formatting is problematic
                channel.send(b"-bash: free: Permission denied\r\n")
            elif command == b"df":
                normal, _ = get_disk_stats()
                channel.send(normal + b"\r\n")
            elif command == b"df -h":
                _, human = get_disk_stats()
                channel.send(human + b"\r\n")
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
