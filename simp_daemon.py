import socket
import threading
import struct

class UdpDaemon:
    def __init__(self, host):
        self.daemon_address = (host, 7777)  # Daemon-to-daemon communication on port 7777
        self.client_address = None  # To store the connected client address (port 7778)
        self.daemons = {}  # Known daemons (address: (host, port))
        self.client_username = None  # Username of the connected client

        # Daemon socket for communication with other daemons
        self.daemon_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.daemon_sock.bind(self.daemon_address)
        
        # Client socket for communication with client
        self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_sock.bind((host, 7778))

        # Predefined daemon addresses
        self.default_daemons = []

    def create_datagram(self, datagram_type, operation, sequence, user, payload=""):
        """Create a SIMP datagram."""
        user_padded = user.encode('ascii').ljust(32, b'\x00')[:32]  # Ensure 32 bytes for the user field
        length = len(payload)
        header = struct.pack('!BB1B32sI', datagram_type, operation, sequence, user_padded, length)
        return header + payload.encode('ascii')

    def parse_datagram(self, datagram):
        """Parse a SIMP datagram into its components."""
        header = datagram[:39]
        payload = datagram[39:].decode('ascii')
        datagram_type, operation, sequence, user_padded, length = struct.unpack('!BB1B32sI', header)
        user = user_padded.decode('ascii').rstrip('\x00')  # Remove padding
        return datagram_type, operation, sequence, user, length, payload

    def send_message_to_daemons(self, username, message):
        """Send a message with username to all known daemons."""
        formatted_message = f"{username}: {message}"
        datagram = self.create_datagram(0x02, 0x01, 0, username, formatted_message)
        for address in self.daemons.values():
            self.daemon_sock.sendto(datagram, address)

    def forward_to_client(self, message):
        """Forward a message to the connected client."""
        if self.client_address:
            datagram = self.create_datagram(0x02, 0x01, 0, self.client_username, message)
            self.client_sock.sendto(datagram, self.client_address)

    def handle_daemon_messages(self):
        """Handle messages from other daemons."""
        while True:
            data, address = self.daemon_sock.recvfrom(1024)
            datagram_type, operation, sequence, user, length, payload = self.parse_datagram(data)

            # Add sender to known daemons if new
            if address not in self.daemons.values() and address != self.daemon_address:
                self.daemons[address] = address
                print(f"Added new daemon: {address}")

            # Forward the message to the client
            if datagram_type == 0x02:  # Chat message
                self.forward_to_client(payload)

    def handle_client_messages(self):
        """Handle messages from the connected client."""
        while True:
            data, address = self.client_sock.recvfrom(1024)
            datagram_type, operation, sequence, user, length, payload = self.parse_datagram(data)

            # If the client is not yet registered, register it
            if self.client_address is None:
                self.client_address = address
                print(f"Client connected from {self.client_address}")

            # If username is not yet set, interpret the first message as the username
            if self.client_username is None:
                self.client_username = user
                print(f"Client username set to {self.client_username}")

                # Broadcast that this user has joined
                self.send_message_to_daemons(self.client_username, "has joined the chat!")
                self.forward_to_client(f"Welcome, {self.client_username}!")
                continue

            # Broadcast the client's message to all other daemons
            print(f"From client: {payload}")
            self.send_message_to_daemons(self.client_username, payload)

    def discover_daemons(self):
        """Send a discovery message to all default daemons."""
        discovery_message = "DISCOVER"
        for daemon in self.default_daemons:
            if daemon != self.daemon_address:  # Exclude self from discovery
                datagram = self.create_datagram(0x01, 0x01, 0, "DISCOVER", discovery_message)
                self.daemon_sock.sendto(datagram, daemon)

    def start(self):
        """Start the daemon to handle client and daemon messages."""
        print(f"Daemon started. Listening on {self.daemon_address} for daemons.")
        print("Listening on port 7778 for client connections.")

        # Send discovery messages
        self.discover_daemons()

        # Start separate threads for daemon and client communication
        threading.Thread(target=self.handle_daemon_messages, daemon=True).start()
        threading.Thread(target=self.handle_client_messages, daemon=True).start()

        while True:
            pass

if __name__ == "__main__":
    host = input("Enter daemon host (IP address this daemon will run on, e.g., 127.0.0.1): ")
    daemon = UdpDaemon(host)

    print("\n=== Configure Other Known Daemons ===")
    while True:
        other_host = input("Enter another daemon IP (or press Enter to finish): ")
        if not other_host:
            break
        daemon.default_daemons.append((other_host, 7777))

    print(f"\nKnown daemons: {daemon.default_daemons}\n")
    daemon.start()
