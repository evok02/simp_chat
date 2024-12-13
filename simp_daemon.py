import socket
import struct
import threading

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

class SIMPDaemon:
    def __init__(self, ip):
        self.ip = ip
        self.clients = {}  # {address: username}
        self.pending_requests = {}  # {client_address: (requesting_address, requesting_username)}
        self.active_chats = {}  # {client_address: partner_address}
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((ip, PORT_DAEMON))
        print(f"Daemon running on {ip}:{PORT_DAEMON}")

    def start(self):
        while True:
            data, addr = self.socket.recvfrom(BUFFER_SIZE)
            print(f"Received connection from {addr}")
            self.handle_client(data, addr)

    def handle_client(self, data, addr):
        header = data[:38]
        payload = data[38:]
        msg_type, operation, user, length = struct.unpack(HEADER_FORMAT, header)
        username = user.decode('ascii').strip('\x00')

        if msg_type == TYPE_CONTROL:
            if operation == OP_SYN:
                self.handle_syn(addr, username, payload.decode('ascii'))
            elif operation == OP_FIN:
                self.handle_fin(addr)
        elif msg_type == TYPE_CHAT:
            self.route_message(addr, payload.decode('ascii'))

    def handle_syn(self, addr, username, target_ip):
        if addr in self.active_chats:
            self.send_error(addr, "Already in a chat")
        elif addr in self.pending_requests:
            self.send_error(addr, "Already has a pending request")
        else:
            self.pending_requests[addr] = (target_ip, username)
            print(f"Chat request from {username} at {addr} for {target_ip}")
            # Forward the chat request to the target client
            target_addr = (target_ip, PORT_CLIENT)
            header = struct.pack(HEADER_FORMAT, TYPE_CONTROL, OP_SYN, username.encode('ascii'), 0)
            self.socket.sendto(header, target_addr)

    def handle_fin(self, addr):
        if addr in self.active_chats:
            partner = self.active_chats.pop(addr)
            self.active_chats.pop(partner, None)
            print(f"Chat ended between {addr} and {partner}")

    def route_message(self, addr, message):
        if addr in self.active_chats:
            partner = self.active_chats[addr]
            self.socket.sendto(message.encode('ascii'), partner)
        else:
            self.send_error(addr, "No active chat")

    def send_error(self, addr, message):
        print(f"Sending error to {addr}: {message}")
        error_msg = struct.pack(HEADER_FORMAT, TYPE_CONTROL, OP_ERR, b'Error', len(message))
        self.socket.sendto(error_msg + message.encode('ascii'), addr)

# Example usage
if __name__ == "__main__":
    daemon = SIMPDaemon("127.0.0.1")
    daemon_thread = threading.Thread(target=daemon.start)
    daemon_thread.start()