import paramiko

# Define SSH credentials
hostname = "your_remote_host"
username = "your_username"
password = "your_password"  # Use key authentication if possible

# Create an SSH client
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    # Connect to the remote server
    client.connect(hostname, username=username, password=password, timeout=10)

    # Run a simple command
    stdin, stdout, stderr = client.exec_command('echo "Hello, World!"')

    # Print the output
    print(stdout.read().decode().strip())

except Exception as e:
    print(f"SSH connection failed: {e}")

finally:
    client.close()
