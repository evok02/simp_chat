import socket
import threading

class UdpClient:
    def __init__(self, daemon_host):
        self.daemon_address = (daemon_host, 7778)  # Connect to daemon's client port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.username = None

    def send_message(self, message):
        """Send a message to the daemon."""
        self.sock.sendto(message.encode(), self.daemon_address)

    def receive_messages(self):
        """Listen for incoming messages from the daemon."""
        while True:
            data, _ = self.sock.recvfrom(1024)
            print(data.decode())  # Print messages received from the daemon

    def start(self):
        """Start the client."""
        self.username = input("Enter your username: ")
        self.send_message(self.username)  # Send the username to the daemon

        print("\nYou can now send messages. Type your message and press Enter.")
        threading.Thread(target=self.receive_messages, daemon=True).start()

        while True:
            message = input()
            self.send_message(message)

if __name__ == "__main__":
    daemon_host = input("Enter the IP address of the daemon to connect to: ")
    client = UdpClient(daemon_host)
    client.start()
