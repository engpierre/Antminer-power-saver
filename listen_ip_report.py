import socket
import json

def listen():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        s.bind(('', 14235))
        s.settimeout(25)
        print("Listening for Antminer IP Report broadcasts on UDP port 14235...")
        while True:
            try:
                data, addr = s.recvfrom(2048)
                print(f"[IP REPORT DETECTED] From {addr[0]}:{addr[1]}")
                print(f"Data: {data}")
                try:
                    info = json.loads(data.decode(errors='replace'))
                    print("JSON Details:", info)
                except:
                    pass
                return addr[0]
            except socket.timeout:
                print("No IP Report broadcast received within timeout.")
                return None
    finally:
        s.close()

if __name__ == "__main__":
    listen()
