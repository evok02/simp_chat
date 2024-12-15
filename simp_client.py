import socket
import threading
import struct

class UdpClient:
    def __init__(self, daemon_host):
        self.daemon_address = (daemon_host, 7778)  # Connect to daemon's client port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.username = None

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

    def send_message(self, message):
        """Send a message to the daemon in SIMP format."""
        datagram = self.create_datagram(0x02, 0x01, 0, self.username, message)  # 0x02 - Chat message
        self.sock.sendto(datagram, self.daemon_address)

    def receive_messages(self):
        """Listen for incoming messages from the daemon."""
        while True:
            data, _ = self.sock.recvfrom(1024)
            datagram_type, operation, sequence, user, length, payload = self.parse_datagram(data)
            if datagram_type == 0x02:  # Chat message
                print(f"{user}: {payload}")  # Print the message received from the daemon

    def start(self):
        """Start the client."""
        self.username = input("Enter your username: ")
        datagram = self.create_datagram(0x01, 0x01, 0, self.username, "has joined the chat!")  # 0x01 - Connection message
        self.sock.sendto(datagram, self.daemon_address)  # Send the username to the daemon

        print("\nYou can now send messages. Type your message and press Enter.")
        threading.Thread(target=self.receive_messages, daemon=True).start()

        while True:
            message = input()
            self.send_message(message)

if __name__ == "__main__":
    daemon_host = input("Enter the IP address of the daemon to connect to: ")
    client = UdpClient(daemon_host)
    client.start()
