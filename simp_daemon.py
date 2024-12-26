import socket
import threading
import struct
import time

class UdpDaemon:
    def __init__(self, host):
        self.daemon_address = (host, 7777)  # Daemon-to-daemon communication
        self.client_address = None
        self.connected_daemon = None
        self.client_username = None
        self.handshake_completed = False
        self.active_chat = False

        # Daemon socket for communication with other daemons
        self.daemon_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.daemon_sock.bind(self.daemon_address)

        # Client socket for communication with client
        self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_sock.bind((host, 7778))

    def create_datagram(self, datagram_type, operation, sequence, user, payload=""):
        """Create a SIMP datagram."""
        user_padded = user.encode('ascii').ljust(32, b'\x00')[:32]
        length = len(payload)
        header = struct.pack('!BB1B32sI', datagram_type, operation, sequence, user_padded, length)
        return header + payload.encode('ascii')

    def parse_datagram(self, datagram):
        """Parse a SIMP datagram into its components."""
        header = datagram[:39]
        payload = datagram[39:].decode('ascii')
        datagram_type, operation, sequence, user_padded, length = struct.unpack('!BB1B32sI', header)
        user = user_padded.decode('ascii').rstrip('\x00')
        return datagram_type, operation, sequence, user, length, payload

    def send_to_client(self, datagram):
        """Send a datagram to the client."""
        if self.client_address:
            self.client_sock.sendto(datagram, self.client_address)

    def send_to_daemon(self, datagram):
        """Send a datagram to the connected daemon."""
        if self.connected_daemon:
            self.daemon_sock.sendto(datagram, self.connected_daemon)

    def handle_client_messages(self):
        """Handle client messages and perform handshake."""
        while True:
            data, address = self.client_sock.recvfrom(1024)
            datagram_type, operation, sequence, user, length, payload = self.parse_datagram(data)

            if self.client_address is None:
                self.client_address = address

            # Handshake process
            if not self.handshake_completed:
                if operation == 0x10:  # SYN
                    print(f"Received SYN from {user}")
                    if self.active_chat:
                        err_datagram = self.create_datagram(0x01, 0x01, 0, user, "User already in another chat")
                        self.send_to_client(err_datagram)
                        fin_datagram = self.create_datagram(0x01, 0x08, 0, user)
                        self.send_to_client(fin_datagram)
                    else:
                        self.client_username = user
                        syn_ack_datagram = self.create_datagram(0x01, 0x06, 0, user, "SYN+ACK")  # SYN+ACK
                        self.send_to_client(syn_ack_datagram)
                        print("Sent SYN+ACK")
                elif operation == 0x12:  # ACK
                    print("Received ACK. Handshake complete.")
                    self.handshake_completed = True
                    self.active_chat = True
                    self.send_to_client(self.create_datagram(0x01, 0x04, 0, user, "Chat ready"))
                continue

            # Handle chat messages
            if datagram_type == 0x02 and self.active_chat:
                print(f"From client: {payload}")
                self.send_to_daemon(data)

            # Termination (FIN)
            if operation == 0x08:  # FIN
                print("Received FIN from client.")
                self.active_chat = False
                ack_datagram = self.create_datagram(0x01, 0x04, 0, user, "ACK")
                self.send_to_client(ack_datagram)
                print("Chat terminated.")
                self.handshake_completed = False
                self.client_address = None
                self.client_username = None

    def handle_daemon_messages(self):
        """Handle messages from other daemons."""
        while True:
            data, address = self.daemon_sock.recvfrom(1024)
            datagram_type, operation, sequence, user, length, payload = self.parse_datagram(data)

            if self.connected_daemon is None:
                self.connected_daemon = address

            # Forward chat messages to client
            if datagram_type == 0x02:
                self.send_to_client(data)

            # Acknowledge messages (Stop-and-Wait)
            if operation == 0x04:  # ACK
                print(f"Received ACK from daemon {address}.")

    def start(self):
        """Start the daemon."""
        print(f"Daemon started at {self.daemon_address}")
        threading.Thread(target=self.handle_client_messages, daemon=True).start()
        threading.Thread(target=self.handle_daemon_messages, daemon=True).start()
        while True:
            pass

if __name__ == "__main__":
    host = input("Enter daemon host (e.g., 127.0.0.1): ")
    daemon = UdpDaemon(host)
    daemon.start()
