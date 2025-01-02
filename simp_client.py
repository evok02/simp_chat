import socket
import threading
import struct
import sys


last_seq = 0x00
class UdpClient:
    
    def __init__(self, daemon_host):
        self.daemon_address = (daemon_host, 7778)  # Connect to daemon's client port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.username = None
        self.recieve_thread = None
        self.input_thread = None
        self.running = True
        self.wait_for_reply = threading.Event()
        self.message_received = threading.Condition()
        self.is_chatting = False

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

    def request_chat(self, ip):
        datagram = self.create_datagram(0x01, 0x02, 0, self.username, ip)
        self.sock.sendto(datagram, self.daemon_address)
    
    def disconnect_from_daemon(self):
        datagram = self.create_datagram(0x01, 0x08, 0, self.username, "disconnect")
        self.sock.sendto(datagram, self.daemon_address)
        print("Disconnected from the daemon.")
        self.reconnect_to_daemon()
        # self.running = False
        self.is_chatting = False
        with self.message_received:
            self.message_received.notify()  # Notify to unblock waiting
        self.receive_thread.join()
        self.input_thread.join()
        self.sock.close()
        sys.exit(0)

    def reconnect_to_daemon(self):
        reconnect = input('Enter IP for daemon to connect ')
        client = UdpClient(reconnect)
        client.start()

    def send_message(self, message):
        """Send a message to the daemon in SIMP format."""
        if message.lower() == "q":
            self.disconnect_from_daemon()
        else:
            if self.is_chatting == False and message.upper() == "YES":
                datagram = self.create_datagram(0x01, 0x04, 0, self.username, "")
                self.sock.sendto(datagram, self.daemon_address)
                datagram = self.create_datagram(0x01, 0x02, 0, self.username, "Connection accepted")
                self.sock.sendto(datagram, self.daemon_address)
                self.is_chatting == True
            elif self.is_chatting == False and message.upper() == "NO":
                datagram = self.create_datagram(0x01, 0x08, 0, self.username, "Invitation declined")
                self.sock.sendto(datagram, self.daemon_address)
                print("Invitation declined. Returning to default state.")
                self.prompt_for_action()
            else:
                datagram = self.create_datagram(0x02, 0x01, 0x00, self.username, message)  # 0x02 - Chat message
                self.sock.sendto(datagram, self.daemon_address)
                self.wait_for_reply.clear()  # Block until a reply is received
                self.wait_for_reply.wait()

        
    def receive_messages(self):
        """Listen for incoming messages from the daemon."""
        while self.running:
            try:
                data, _ = self.sock.recvfrom(1024)
                datagram_type, operation, sequence, user, length, payload = self.parse_datagram(data)
                if datagram_type == 0x01:
                    if operation == 0x02:
                        print(f'{payload}')
                    if operation == 0x08:
                        print(f'{payload}')
                        self.reconnect_to_daemon()
                if datagram_type == 0x02:  # Chat message
                    print(f"{payload} ") 
                    self.wait_for_reply.set()  # Print the message received from the daemon

            except OSError:
                print("Stopped from receiving messages")
                break

    def input_thread_func(self):
        """Thread for handling user input."""
        while self.running:
            try:
                message = input()
                self.send_message(message)
            except EOFError:
                break
    
    def prompt_for_action(self):
        """Prompt the user to start a new chat or wait for chat requests."""
        while self.running:
            choice = input('\nDo you want to start a new chat or wait for chat requests? (start/wait): ')
            if choice.lower() == 'start':
                connect_to = input('Enter IP of the user to connect: ')
                self.request_chat(connect_to)
                break
            elif choice.lower() == 'wait':
                print('Waiting for incoming chat requests...')
                break
            elif choice.lower() == 'q':
                self.disconnect_from_daemon()
            else:
                print('Invalid choice. Please enter "start" or "wait".')

    def start(self):
        """Start the client."""
        self.username = input("Enter your username: ")
        datagram = self.create_datagram(0x02, 0x01, 0, self.username, "has joined the chat!")  # 0x01 - Connection message
        self.sock.sendto(datagram, self.daemon_address)  # Send the username to the daemon

        self.prompt_for_action()

        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.start()
        self.input_thread = threading.Thread(target=self.input_thread_func)
        self.input_thread.start()

       

        self.receive_thread.join()
        self.input_thread.join()


if __name__ == "__main__":
    daemon_host = sys.argv[1]
    # daemon_host = input("Enter the IP address of the daemon to connect to: ")
    client = UdpClient(daemon_host)
    client.start()


#192.168.50.107
