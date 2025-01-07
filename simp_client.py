import socket
import threading
import struct
import sys


class UdpClient:

    def __init__(self, daemon_host):
        # Initialize client settings
        self.daemon_address = (daemon_host, 7778)  # Daemon's client port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create UDP socket
        self.username = None
        self.receive_thread = None
        self.input_thread = None
        self.running = True  # Client running state
        self.wait_for_reply = threading.Event()  # Synchronization for replies
        self.message_received = threading.Condition()  # For advanced control over received messages
        self.is_chatting = False  # Tracks whether client is in a chat

    def create_datagram(self, datagram_type, operation, sequence, user, payload=""):
        """Create a SIMP datagram for communication."""
        user_padded = user.encode('ascii').ljust(32, b'\x00')[:32]  # Pad username to 32 bytes
        length = len(payload)  # Length of the payload
        # Pack datagram header with payload
        header = struct.pack('!BB1B32sI', datagram_type, operation, sequence, user_padded, length)
        return header + payload.encode('ascii')

    def parse_datagram(self, datagram):
        """Parse a received SIMP datagram."""
        header = datagram[:39]  # Extract header
        payload = datagram[39:].decode('ascii')  # Decode payload
        # Unpack header into fields
        datagram_type, operation, sequence, user_padded, length = struct.unpack('!BB1B32sI', header)
        user = user_padded.decode('ascii').rstrip('\x00')  # Remove padding from username
        return datagram_type, operation, sequence, user, length, payload
    
    def send_err(self, message):
        """Send an ERR message to the daemon."""
        try:
            err_datagram = self.create_datagram(0x01, 0x01, 0x00, self.username, message)
            self.sock.sendto(err_datagram, self.daemon_address)
        except Exception as e:
            print(f"Can't send the ERR: {e}")

    def request_chat(self, ip):
        """Send a chat request to another user."""
        datagram = self.create_datagram(0x01, 0x02, 0, self.username, ip)
        self.sock.sendto(datagram, self.daemon_address)  # Send request to daemon
        self.is_chatting = True  # Mark as chatting

    def disconnect_from_daemon(self):
        """Disconnect client from daemon."""
        datagram = self.create_datagram(0x01, 0x08, 0, self.username, "disconnect")
        self.sock.sendto(datagram, self.daemon_address)  # Notify daemon about disconnection
        print("Disconnected from the daemon.")
        self.running = False  # Stop client
        self.is_chatting = False  # Reset chat state
        self.sock.close()  # Close socket
        sys.exit(0)  # Exit program

    def reconnect_to_daemon(self):
        """Reconnect client to a new daemon."""
        reconnect = input('Enter IP for daemon to connect ')
        client = UdpClient(reconnect)
        client.start()

    def send_message(self, message):
        """Send a message to the daemon in SIMP format."""
        if message.lower() == "q":
            if not self.is_chatting:  # Disconnect if not chatting
                self.disconnect_from_daemon()
            else:  # Send disconnect message to daemon
                datagram = self.create_datagram(0x01, 0x08, 0, self.username, "disconnect")
                self.sock.sendto(datagram, self.daemon_address)
                self.is_chatting = False  # Reset chat state
                self.prompt_for_action()  # Prompt for next action

        else:
            if not self.is_chatting and message.upper() == "YES":  # Accept chat invitation
                datagram = self.create_datagram(0x01, 0x04, 0, self.username, "")
                self.sock.sendto(datagram, self.daemon_address)
                datagram = self.create_datagram(0x01, 0x02, 0, self.username, "Connection accepted")
                self.sock.sendto(datagram, self.daemon_address)
                self.is_chatting = True
            elif not self.is_chatting and message.upper() == "NO":  # Decline chat invitation
                datagram = self.create_datagram(0x01, 0x08, 0, self.username, "Invitation declined")
                self.sock.sendto(datagram, self.daemon_address)
                print("Invitation declined. Returning to default state.")
                self.prompt_for_action()  # Prompt for next action
            elif not self.is_chatting:  # Not chatting case
                print("You are not chatting to anybody...")
            else:  # Send regular chat message
                datagram = self.create_datagram(0x02, 0x01, 0x00, self.username, message)  # 0x02 - Chat message
                self.sock.sendto(datagram, self.daemon_address)
                self.wait_for_reply.clear()  # Block until a reply is received
                self.wait_for_reply.wait()

    def receive_messages(self):
        """Listen for incoming messages from the daemon."""
        while self.running:
            try:
                data, _ = self.sock.recvfrom(1024)  # Receive message
                datagram_type, operation, sequence, user, length, payload = self.parse_datagram(data)
                if datagram_type == 0x01:  # Control message
                    if operation == 0x02:  # Chat request or status message
                        print(f'{payload}')
                    elif operation == 0x08:  # Disconnect message
                        self.is_chatting = False  # Reset chat state
                        print(f'{payload}')
                        self.prompt_for_action()  # Prompt for next action
                elif datagram_type == 0x02:  # Chat message
                    print(f"{payload}")
                    if "User is busy in another chat." in payload:  # Handle busy message
                        self.is_chatting = False
                        self.prompt_for_action()
                self.wait_for_reply.set()  # Notify that reply was received
            except OSError:
                print("Stopped from receiving messages")  # Handle socket error
                break

    def input_thread_func(self):
        """Thread for handling user input."""
        while self.running:
            try:
                message = input()  # Get input from user
                self.send_message(message)  # Send message to daemon
            except EOFError:
                break

    def prompt_for_action(self):
        """Prompt the user to start a new chat or wait for chat requests."""
        while self.running:
            try:
                choice = input('\nDo you want to start a new chat or wait for chat requests? (start/wait): ')
                if choice.lower() == 'start':  # Start new chat
                    connect_to = input('Enter IP of the user to connect: ')
                    self.request_chat(connect_to)
                    break
                elif choice.lower() == 'wait':  # Wait for chat requests
                    print('Waiting for incoming chat requests...')
                    break
                elif choice.lower() == 'q':  # Quit client
                    self.disconnect_from_daemon()
                else:  # Handle invalid input
                    print('Invalid choice. Please enter "start" or "wait".')
            except Exception as e:
                print(f"Error in prompt_for_action: {e}")
                self.send_err(f"Failed in prompt_for_action: {e}")


    def start(self):
        try:
            """Start the client."""
            self.username = input("Enter your username: ")  # Prompt user for username
            datagram = self.create_datagram(0x02, 0x01, 0, self.username, "has joined the chat!")  # Connection message
            self.sock.sendto(datagram, self.daemon_address)  # Notify daemon about new user

            self.prompt_for_action()  # Prompt user for action

            # Start threads for receiving messages and user input
            self.receive_thread = threading.Thread(target=self.receive_messages)
            self.receive_thread.start()
            self.input_thread = threading.Thread(target=self.input_thread_func)
            self.input_thread.start()

            # Wait for threads to finish
            self.receive_thread.join()
            self.input_thread.join()
        except Exception as e:
            print(f"Error in start: {e}")
            self.send_err(f"Failed to start client: {e}")


if __name__ == "__main__":
    try:
        # Get daemon host address from command line arguments
        daemon_host = sys.argv[1]
        client = UdpClient(daemon_host)
        client.start()
    except Exception as e:
        print(f"Error in main: {e}")
        client.send_err(f"Failed to start client from main: {e}")
