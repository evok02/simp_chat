import socket
import threading

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

    def send_message_to_daemons(self, username, message):
        """Send message with username to all known daemons."""
        formatted_message = f"{username}: {message}"
        for address in self.daemons.values():
            self.daemon_sock.sendto(formatted_message.encode(), address)

    def forward_to_client(self, message):
        """Forward a message to the connected client."""
        if self.client_address:
            self.client_sock.sendto(message.encode(), self.client_address)

    def handle_daemon_messages(self):
        """Handle messages from other daemons."""
        while True:
            data, address = self.daemon_sock.recvfrom(1024)
            
            # Add sender to known daemons if new
            if address not in self.daemons.values() and address != self.daemon_address:
                self.daemons[address] = address
                print(f"Added new daemon: {address}")

            # Forward the message to the client
            self.forward_to_client(data.decode())

    def handle_client_messages(self):
        """Handle messages from the connected client."""
        while True:
            data, address = self.client_sock.recvfrom(1024)
            
            # If the client is not yet registered, register it
            if self.client_address is None:
                self.client_address = address
                print(f"Client connected from {self.client_address}")

            # If username is not yet set, interpret the first message as the username
            if self.client_username is None:
                self.client_username = data.decode()
                print(f"Client username set to {self.client_username}")

                # Broadcast that this user has joined
                self.send_message_to_daemons(self.client_username, "has joined the chat!")
                self.forward_to_client(f"Welcome, {self.client_username}!")
                continue

            # Broadcast the client's message to all other daemons
            print(f"From client: {data.decode()}")
            self.send_message_to_daemons(self.client_username, data.decode())


    def discover_daemons(self):
        """Send a discovery message to all default daemons."""
        discovery_message = "DISCOVER"
        for daemon in self.default_daemons:
            if daemon != self.daemon_address:  # Exclude self from discovery
                self.daemon_sock.sendto(discovery_message.encode(), daemon)

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



#192.168.1.255
#192.168.1.20