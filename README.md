# Buzzpy

Configurable honeypot system featuring a real-time dashboard for monitoring and analyzing intrusion attempts. Designed for security research and threat intelligence gathering.

## This project is still in early development!

The focus so far has been to add features and establish a direction for this tools development, even though there have been security considerations during the design and impletation phases, there has been no thorough security testing. 

TLDR: **The use of these tool in production environments is not recomended as of now.**

## **Features**

- [x] **SSH honeypot**
    - Simulates an SSH server to capture login attempts and commands.
    - Logs credentials and emulates a restricted shell environment with realistic responses.
    - Supports dynamic uptime, process list, and user session emulation.

- [x] **Web honeypot**
    - Simulates a WordPress login page and admin panel to capture login attempts and HTTP requests.
    - Logs credentials and redirects unauthorized login attempts.
    - Logs URL parameter separately to more easily identify web attacks.

- [x] **Real-time dashboard**
    - Interactive interface displaying captured data intuitively like top IPs and geolocation analysis.
    - Supports filtering by service type, localization, and dynamic data refresh.
    - Built with Dash and Plotly for a modern and responsive user experience.

- [x] **General features**
    - Modular and multi-threaded design for scalability and easy configuration.
    - Rotating log files to manage disk usage effectively.
    - Environment variable support and `.gitignore` that protects sensitive data such as RSA keys and logs for secure and efficient development.
    - **Demo mode**: Allows demonstration and testing with using obvious strings to easily tell the difference between a honeypot deployment and a real deployment. 


## **Installation**


1. **Clone the Repository**

```shell
git clone https://github.com/Kaassal/buzzpy.git
```

2. **Set up a virtual environment**  

Create and activate a virtual environment to isolate dependencies:

Create a venv:

```shell
python3 -m venv Buzzpy_venv
```

And run it
```shel
source /Buzzpy_venv/bin/activate
```

**Note:** This step is not strictly necessary, a system wide install could be performed, however the creation of a venv is highly recomended to avoid any problems regarding dependencies.

3. **Install Dependencies**  

These are found in `requirements.txt`

First go into the projects folder:

```shell
cd Buzzpy
```

Then install the required dependencies 

```shell
pip install -r requirements.txt
```


4. **Keygen**  

The ssh honeypot requieres a pair of RSA keys, the key must be named **server.key** and it must be on the on the same directory used as the requirements.txt file is, so if you are following these steps you should be on the right directory.

5. **Set Up Environment Variables**  
Ensure the `public.env` file is properly configured. 

**Country code lookup in enabled by default**. 

If you **do not want** to make api calls to check the country code of the logged ip adresses the `public.env` file has to look like this. 

```
COUNTRY=False
```

**Note:** The country code lookup uses [this api](https://cleantalk.org/help/api-ip-info-country-code) by clean talk, there is a call limit by minute but no api key is required.


## **Usage**

Buzzpy provides three main functionalities: an SSH honeypot, a web honeypot, and a real-time dashboard. Below are the detailed usage instructions for each component.

### **1. SSH Honeypot**
The SSH honeypot simulates an SSH server to capture login attempts and commands.

#### **Command**
```bash
python buzzpy.py -s -a <address> -p <port> -u <username> -P <password> [-d]
```

#### **Arguments**
- `-s` or `--ssh`: Run the SSH honeypot.
- `-a` or `--address`: IP address to bind the honeypot.
- `-p` or `--port`: Port number to bind the honeypot.
- `-u` or `--username`: Username for authentication.
- `-P` or `--password`: Password for authentication.
- `-d` or `--demo`: (Optional) Run in demo mode with obvious honeypot strings.

#### **Example**
```bash
python buzzpy.py -s -a 127.0.0.1 -p 2222 -u admin -P password 
```
This starts the SSH honeypot on `127.0.0.1:2222` with the username `admin` and password `password`.

---

### **2. Web Honeypot**
The web honeypot simulates a WordPress login page and admin panel to capture login attempts and HTTP requests.

#### **Command**
```bash
python buzzpy.py -w -a <address> -p <port> -u <username> -P <password> [-d]
```

#### **Arguments**
- `-w` or `--web`: Run the web honeypot.
- `-a` or `--address`: IP address to bind the honeypot.
- `-p` or `--port`: Port number to bind the honeypot.
- `-u` or `--username`: Username for authentication.
- `-P` or `--password`: Password for authentication.
- `-d` or `--demo`: (Optional) Run in demo mode with obvious honeypot strings.

#### **Example**
```bash
python buzzpy.py -w -a 127.0.0.1 -p 8080 -u admin -P password
```
This starts the web honeypot on `127.0.0.1:8080` with the username `admin` and password `password`.

---

### **3. Real-Time Dashboard**
The dashboard provides an interactive interface to monitor and analyze data captured by the honeypots.

#### **Command**
```bash
python buzzpy.py -D -a <address> -p <port>
```

#### **Arguments**
- `-D` or `--dashboard`: Run the dashboard.
- `-a` or `--address`: IP address to bind the dashboard.
- `-p` or `--port`: Port number to bind the dashboard.

#### **Example**
```bash
python buzzpy.py -D -a 127.0.0.1 -p 8050
```
This starts the dashboard on `127.0.0.1:8050`.

#### **Access**
Open a web browser and navigate to `http://<address>:<port>` (e.g., `http://127.0.0.1:8050`) to view the dashboard.

---
### **4. Demo Mode**
Demo mode can be enabled for both honeypots using the `-d` flag. In this mode:
- The SSH honeypot uses demo strings (e.g., fake banners and responses including "honeypot").
- The web honeypot displays demo server headers and WordPress version strings.

#### **Example**
```bash
python buzzpy.py -s -a 127.0.0.1 -p 2222 -u admin -P password -d
```

This starts the SSH honeypot in demo mode.

---
### **5. Logs**
Captured data is stored in the `log_files` directory:
- **SSH Honeypot Logs**:
  - `audits.log`: Captures login attempts 
	  - username 
	  - password
	  - timestamp
	  - IP
  - `cmd_audits.log`: Captures commands executed by attackers/auditors.
  
- **Web Honeypot Logs**:
  - `http_audits.log`: Captures login attempts (username and password).
	  - username 
	  - password
	  - timestamp
	  - IP
  - `http_url_audits.log`: Captures HTTP requests 
	  - URLs
	  - Methods
	  - Parameters
	  - IP
	  - timestamp

Logs are rotated automatically to manage disk usage.

**Note:** The log_files directory will be created automatically if it does not exist

---

## **Future features**

TBC
