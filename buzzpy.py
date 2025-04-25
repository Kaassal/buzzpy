# Import Libraries
import argparse
from ssh_honeypot import *
from web_honeypot import web_honeypot

# Argument Parsing
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Buzzpy - A configurable SSH and Web honeypot")

    parser.add_argument("-a", "--address", type=str, required=True, help="IP address to bind")
    parser.add_argument("-p", "--port", type=int, required=True, help="Port to bind")
    parser.add_argument("-u", "--username", type=str, help="Username for authentication")
    parser.add_argument("-P", "--password", type=str, help="Password for authentication")
    parser.add_argument("-d", "--demo", action="store_true", help="Run in demo mode with obvious honeypot strings")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-s", "--ssh", action="store_true", help="Run SSH honeypot")
    group.add_argument("-w", "--web", action="store_true", help="Run web honeypot")

    args = parser.parse_args()

    try:
        if args.ssh:
            print("[-] Running SSH honeypot...")
            honeypot(args.address, args.port, args.username, args.password, demo_mode=args.demo)
        elif args.web:
            print("[!] Running web honeypot...")
            web_honeypot(args.address, args.port, args.username, args.password, demo_mode=args.demo)
    except Exception as e:
        print(f"Error: {e}")
        print("\n Exiting Buzzpy, cya!")
