# Import Libraries
import argparse
from ssh_honeypot import *  # Asegúrate de importar correctamente la función honeypot

# Argument Parsing
if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('-a','--address', type=str, required=True)
    parser.add_argument('-p', '--port', type=int, required=True)
    parser.add_argument('-u', '--username', type=str)
    parser.add_argument('-P', '--password', type=str)

    parser.add_argument('-s','--ssh', action="store_true")
    parser.add_argument('-w', '--web', action="store_true")  #TODO: Code this up

    args = parser.parse_args()

    # Depuración de los argumentos
    print(f"Arguments: {args}")

    try:
        if args.ssh:
            print("[-] Running SSH honeypot...")
            honeypot(args.address, args.port, args.username, args.password)  
            if not args.username:
                username:None
            if not args.password:
                password = None
        elif args.web:  
            print("[!] Not yet implemented...")  #TODO: Change this when implemented
            pass  #TODO: Remove this when implemented
        else:
            print("[!] No honeypot specified.")
            print("[?] Hint: Run an SSH honeypot using (-s) or (--ssh), check help for all the options" )
    except Exception as e:
        print(f"Error: {e}")
        print("\n Exiting Buzzpy, cya!")


