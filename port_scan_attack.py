import socket
import time

# Configuration
TARGET_IP = '127.0.0.1'  # Target IP address (localhost for testing)
START_PORT = 1
END_PORT = 1025
TIMEOUT = 1  # Timeout in seconds

def scan_port(ip, port):
    try:
        # Create a new socket using TCP/IP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        
        # Attempt to connect to the target IP and port
        result = sock.connect_ex((ip, port))
        
        # If the connection is successful, result will be 0
        if result == 0:
            print(f"Port {port} is open.")
        sock.close()
    except socket.error as e:
        print(f"Socket error: {e}")
    finally:
        sock.close()

def main():
    print(f"Starting SYN scan on {TARGET_IP} from port {START_PORT} to {END_PORT}")
    
    for port in range(START_PORT, END_PORT):
        scan_port(TARGET_IP, port)
        time.sleep(0.01)  # Short delay to avoid overwhelming the target

    print("Scan complete.")

if __name__ == "__main__":
    main()
