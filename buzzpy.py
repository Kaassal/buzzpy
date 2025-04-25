# Import Libraries
import argparse
from ssh_honeypot import honeypot
from web_honeypot import web_honeypot
from web_dashboard import app as dashboard_app

def run_ssh_honeypot(address, port, username, password, demo_mode):
    """Run SSH honeypot"""
    print("[!] Running SSH honeypot...")
    try:
        honeypot(address, port, username, password, demo_mode=demo_mode)
    except Exception as e:
        print(f"SSH honeypot error: {e}")

def run_web_honeypot(address, port, username, password, demo_mode):
    """Run Web honeypot"""
    print("[!] Running web honeypot...")
    try:
        web_honeypot(address, port, username, password, demo_mode=demo_mode)
    except Exception as e:
        print(f"Web honeypot error: {e}")

def run_dashboard(host, port):
    """Run the dashboard"""
    print("[+] Starting dashboard...")
    try:
        dashboard_app.run(debug=False, host=host, port=port)
    except Exception as e:
        print(f"Dashboard error: {e}")

# Argument Parsing
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Buzzpy - A configurable SSH and Web honeypot")

    parser.add_argument("-a", "--address", type=str, help="IP address to bind")
    parser.add_argument("-p", "--port", type=int, help="Port number")
    parser.add_argument("-u", "--username", type=str, help="Username for authentication")
    parser.add_argument("-P", "--password", type=str, help="Password for authentication")
    parser.add_argument("-d", "--demo", action="store_true", help="Run in demo mode with obvious honeypot strings")
    
    service_group = parser.add_mutually_exclusive_group(required=True)
    service_group.add_argument("-s", "--ssh", action="store_true", help="Run SSH honeypot")
    service_group.add_argument("-w", "--web", action="store_true", help="Run web honeypot")
    service_group.add_argument("-D", "--dashboard", action="store_true", help="Run dashboard")

    args = parser.parse_args()

    try:
        if args.ssh:
            if not all([args.address, args.port, args.username, args.password]):
                print("Error: SSH honeypot requires address, port, username, and password")
                exit(1)
            run_ssh_honeypot(args.address, args.port, args.username, args.password, args.demo)
            
        elif args.web:
            if not all([args.address, args.port, args.username, args.password]):
                print("Error: Web honeypot requires address, port, username, and password")
                exit(1)
            run_web_honeypot(args.address, args.port, args.username, args.password, args.demo)
            
        elif args.dashboard:
            if not all([args.address, args.port]):
                print("Error: Dashboard requires address and port")
                exit(1)
            run_dashboard(args.address, args.port)

    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        print("\nExiting Buzzpy, cya!")
