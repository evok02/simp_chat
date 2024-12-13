import socket
import struct

# Constants
PORT_DAEMON = 7777
PORT_CLIENT = 7778
HEADER_FORMAT = "!BB32sI"  # Type, Operation, User, Length
BUFFER_SIZE = 1024

# SIMP Datagram Types and Operations
TYPE_CONTROL = 0x01
TYPE_CHAT = 0x02
OP_ERR = 0x01
OP_SYN = 0x02
OP_ACK = 0x04
OP_FIN = 0x08

class SIMPClient:
    def __init__(self, daemon_ip):
        self.daemon_ip = daemon_ip
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("", PORT_CLIENT))
        self.username = None
        self.chatting = False

    def run(self):
        self.username = input("Enter your username: ")
        self.connect()
        while True:
            command = input("Enter command (start, wait, quit): ")
            if command == "start":
                target_ip = input("Enter the IP address of the user to chat with: ")
                self.send_syn(target_ip)
            elif command == "wait":
                print("Waiting for chat requests...")
                self.wait_for_requests()
            elif command == "quit":
                self.quit()
                break

    def connect(self):
        print(f"Connecting to daemon at {self.daemon_ip}:{PORT_DAEMON}")

    def send_syn(self, target_ip):
        header = struct.pack(HEADER_FORMAT, TYPE_CONTROL, OP_SYN, self.username.encode('ascii'), len(target_ip))
        self.socket.sendto(header + target_ip.encode('ascii'), (self.daemon_ip, PORT_DAEMON))
        print(f"Sent chat request to {target_ip}")

    def wait_for_requests(self):
        while True:
            data, addr = self.socket.recvfrom(BUFFER_SIZE)
            self.handle_response(data, addr)

    def handle_response(self, data, addr):
        header = data[:38]
        payload = data[38:]
        msg_type, operation, user, length = struct.unpack(HEADER_FORMAT, header)
        message = payload.decode('ascii')
        if operation == OP_ERR:
            print(f"Error from daemon: {message}")
        elif operation == OP_SYN:
            print(f"Chat request from {message}")
            response = input("Accept chat request? (yes/no): ")
            if response == "yes":
                self.send_ack(addr)
                self.chatting = True
                self.chat(addr)
            else:
                self.send_fin(addr)

    def send_ack(self, addr):
        header = struct.pack(HEADER_FORMAT, TYPE_CONTROL, OP_ACK, self.username.encode('ascii'), 0)
        self.socket.sendto(header, addr)
        print(f"Accepted chat request from {addr}")

    def send_fin(self, addr):
        header = struct.pack(HEADER_FORMAT, TYPE_CONTROL, OP_FIN, self.username.encode('ascii'), 0)
        self.socket.sendto(header, addr)
        print(f"Declined chat request from {addr}")

    def chat(self, addr):
        print("Chatting... Type your messages below.")
        while self.chatting:
            message = input()
            if message == "quit":
                self.send_fin(addr)
                self.chatting = False
            else:
                header = struct.pack(HEADER_FORMAT, TYPE_CHAT, 0, self.username.encode('ascii'), len(message))
                self.socket.sendto(header + message.encode('ascii'), addr)

    def quit(self):
        print("Disconnecting from daemon")
        self.socket.close()

# Example usage
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python simp_client.py <daemon_ip>")
        sys.exit(1)
    client = SIMPClient(sys.argv[1])
    client.run()