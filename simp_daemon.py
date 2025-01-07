import socket
import threading
import struct
import sys
import time
from datetime import datetime

# Main class for handling UDP Daemon functionality
class UdpDaemon:
    def __init__(self, host):
        # Address for daemon-to-daemon communication
        self.daemon_address = (host, 7777)
        # Variable to store connected client address
        self.client_address = None
        # Dictionary to keep track of known daemons
        self.daemons = {}
        # Username of the connected client
        self.client_username = None
        # Variables to track last ACK and SYN messages
        self.last_ack_recv = 0x00
        self.last_ack_sent = 0x00
        self.last_syn_sent = 0x00
        self.last_syn_recv = 0x00
        # Flag to check if the client is chatting
        self.client_is_chatting = False
        # Timeout for retransmitting SYN messages
        self.timeout = 5
        # Event for handling ACK received
        self.ack_received_event = threading.Event()
        # Buffer to store unacknowledged SYN messages
        self.syn_buffer = {}

        # Socket for daemon-to-daemon communication
        self.daemon_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.daemon_sock.bind(self.daemon_address)
        
        # Socket for client-to-daemon communication
        self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_sock.bind((host, 7778))

        # List of predefined daemon addresses
        self.default_daemons = []

    # Method to create a SIMP datagram
    def create_datagram(self, datagram_type, operation, sequence, user, payload=""):
        """Create a SIMP datagram."""
        # Ensure username is 32 bytes, padded with null bytes if necessary
        user_padded = user.encode('ascii').ljust(32, b'\x00')[:32]
        # Calculate length of the payload in bytes
        payload_bytes = payload.encode('ascii')
        length = len(payload_bytes)
        # Pack header and payload into a single datagram
        header = struct.pack('!BB1B32sI', datagram_type, operation, sequence, user_padded, length)
        return header + payload_bytes

    # Method to parse an incoming datagram
    def parse_datagram(self, datagram):
        """Parse a SIMP datagram into its components."""
        # Extract header and payload from the datagram
        header = datagram[:39]
        payload = datagram[39:].decode('ascii')
        # Unpack the header and extract fields
        datagram_type, operation, sequence, user_padded, length = struct.unpack('!BB1B32sI', header)
        # Decode and strip padding from the username
        user = user_padded.decode('ascii').rstrip('\x00')
        return datagram_type, operation, sequence, user, length, payload

    # Method to send a message to all known daemons
    def send_message_to_daemons(self, datagram_type, operation, username, message):
        """Send a message with username to all known daemons."""
        if datagram_type == 0x01 and operation == 0x02:
            # If there are no known daemons, send a conversation request
            if len(self.daemons.values()) == 0:
                formatted_message = f'Conversation request is pending...\nDo you want to accept chat with {username}, {self.client_address}'
                # Create SYN datagram with sequence 0x01 or 0x00
                if self.last_syn_sent == 0x00:
                    datagram = self.create_datagram(0x01, 0x02, 0x01, username, formatted_message)
                else:
                    datagram = self.create_datagram(0x01, 0x02, 0x00, username, formatted_message)
                # Send datagram to the requested address
                self.daemon_sock.sendto(datagram, (message, 7777))
            else:
                # Send SYN message to known daemons
                self.send_syn(message)

        if datagram_type == 0x01 and operation == 0x04:
            # Send ACK message to all daemons
            formatted_message = ""
            datagram = self.create_datagram(0x01, 0x04, self.last_syn_recv, username, formatted_message)
            for address in self.daemons.values():
                self.daemon_sock.sendto(datagram, address)
            self.last_ack_sent = self.last_syn_recv

        if datagram_type == 0x01 and operation == 0x08:
            # Handle FIN (end chat) messages
            if self.client_is_chatting:
                formatted_message = f'{username} quit the chat'
                datagram = self.create_datagram(0x01, 0x08, 0, username, formatted_message)
                for address in self.daemons.values():
                    self.daemon_sock.sendto(datagram, address)
            else:
                # If the client is not chatting, notify that the connection was declined
                formatted_message = f"{username} declined the connection"
                datagram = self.create_datagram(0x01, 0x08, 0, username, formatted_message)
                for address in self.daemons.values():
                    self.daemon_sock.sendto(datagram, address)
        else:
            # Send a chat message to all daemons
            formatted_message = f"{username}: {message}"
            datagram = self.create_datagram(0x02, 0x01, 0, username, formatted_message)
            for address in self.daemons.values():
                self.daemon_sock.sendto(datagram, address)

    # Method to send an ACK for a received SYN
    def send_ack(self, sequence):
        """Send ACK for a received SYN."""
        try:
            # Create and send ACK datagram
            datagram = self.create_datagram(0x01, 0x04, sequence, "Server", "")
            for address in self.daemons.values():
                self.daemon_sock.sendto(datagram, address)
            self.last_ack_sent = sequence
        except Exception as e:
            print("Can't send the ACK")
            self.send_err(f"Failed to send ACK: {e}")

    # Method to send a SYN message
    def send_syn(self, message = ""):
        """Send SYN."""
        try:
            # Determine sequence number and create SYN datagram
            sequence = 0x01 if self.last_syn_sent == 0x00 else 0x00
            datagram = self.create_datagram(0x01, 0x02, sequence, self.client_username, message)
            # Store the SYN in the buffer for retransmission
            self.syn_buffer[sequence] = (datagram, time.time())
            # Send the SYN to all known daemons
            for address in self.daemons.values():
                self.daemon_sock.sendto(datagram, address)
            self.last_syn_sent = sequence
            print(f"SYN sent {sequence}")
        except Exception as e:
            print(f"Can't send the SYN {sequence}: {e}")
            self.send_err(f"Failed to send SYN: {e}")

    # Method to send an ERR message
    def send_err(self, message = ""):
        """Send an ERR message."""
        err_datagram = self.create_datagram(0x01, 0x01, 0x00, self.client_username, message)
        for address in self.daemons.values():
            self.daemon_sock.sendto(err_datagram, address)
    
    # Method to retransmit unacknowledged SYNs
    def retransmit_syns(self):
        """Check for unacknowledged SYNs and retransmit if necessary."""
        current_time = time.time()
        for sequence, (datagram, timestamp) in list(self.syn_buffer.items()):
            if current_time - timestamp > self.timeout:
                print(f"Retransmitting SYN with sequence {sequence}")
                for address in self.daemons.values():
                    self.daemon_sock.sendto(datagram, address)
                self.syn_buffer[sequence] = (datagram, current_time)

    # Method to forward a message to the connected client
    def forward_to_client(self, message):
        """Forward a message to the connected client."""
        if self.client_address:
            if message == 'User left chat':
                datagram = self.create_datagram(0x01, 0x08, 0x00, self.client_username, message)
                self.client_sock.sendto(datagram, self.client_address)
            else:
                datagram = self.create_datagram(0x02, 0x01, 0x00, self.client_username, message)
                self.client_sock.sendto(datagram, self.client_address)

    # Method to handle messages from other daemons
    def handle_daemon_messages(self):
        """Handle messages from other daemons."""
        while True:
            try:
                data, address = self.daemon_sock.recvfrom(1024)
                datagram_type, operation, sequence, user, length, payload = self.parse_datagram(data)
                current_time = datetime.now().strftime("%H:%M:%S")
                # Add sender to known daemons if new
                if address not in self.daemons.values() and address != self.daemon_address and not self.client_is_chatting:
                    self.daemons[str(address[1])] = address
                    print(f"Added new daemon: {address}")
                
                # Handle different message types and operations
                if datagram_type == 0x01:
                    # Handling ERR, SYN, ACK, and FIN messages
                    if operation == 0x01:
                        print(f"Received an ERR: {payload}")
                        self.forward_to_client(f"{payload}")
                        del self.daemons[str(address[1])]
                    if operation == 0x02 and not self.client_is_chatting:
                        print(f"Daemon received a SYN {sequence}")
                        self.last_syn_recv = sequence
                        self.forward_to_client(payload)
                    if operation == 0x02 and self.client_is_chatting and address not in self.daemons.values():
                        print("Client is busy. Sending ERR to the sender.")
                        err_message = "User is busy in another chat."
                        err_datagram = self.create_datagram(0x01, 0x01, 0x00, self.client_username, err_message)
                        self.daemon_sock.sendto(err_datagram, address)
                    if operation == 0x02 and self.client_is_chatting and operation != 0x08 :
                        print(f"Received SYN: {payload}, {current_time}")
                        self.send_ack(sequence)
                    elif operation == 0x04:
                        print(f"Daemon received an ACK {sequence}, {current_time}")
                        if not self.client_is_chatting:
                            self.client_is_chatting = True
                        self.last_ack_recv = sequence
                        if sequence in self.syn_buffer:
                            del self.syn_buffer[sequence]
                    elif operation == 0x08:
                        print("Recieved a FIN")
                        if not self.client_is_chatting:
                            datagram = self.create_datagram(0x01, 0x08, 0x00, self.client_username, f"User {user} declined the invitation. \nPress enter to continue...\n")
                            del self.daemons[str(address[1])]
                            self.client_sock.sendto(datagram, self.client_address)
                        else:
                            del self.daemons[str(address[1])]
                            datagram = self.create_datagram(0x01, 0x08, 0x00, self.client_username, f"User {user} left chat")
                            self.client_sock.sendto(datagram, self.client_address)
                            time.sleep(1)
                            self.client_address = None
                            self.daemons = {}  
                            self.client_username = None  
                            self.last_ack_recv = 0x00
                            self.last_ack_sent = 0x00
                            self.last_syn_sent = 0x00
                            self.last_syn_recv = 0x00
                            self.client_is_chatting = False

                # Forward the message to the client
                elif datagram_type == 0x02:  # Chat message
                    self.forward_to_client(payload)
            except ConnectionResetError as e:
                print(f"Connection reset error: {e}")
                self.send_err(f"User {self.client_username} got ConnectionResetError")
                break
            except OSError as e:
                print(f"OSError: {e}")
                self.send_err(f"User {self.client_username} got OSError")
                break
            except Exception as e:
                print(f"Some problem occured: {e}")
                self.send_err(f"User {self.client_username} got some problem")
                break


    def handle_client_messages(self):
        """Handle messages from the connected client."""
        while True:
            try:
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
                    self.send_message_to_daemons(datagram_type, operation, self.client_username, "has joined the chat!")
                    continue

                if datagram_type == 0x01:
                    if operation == 0x01:
                        print(payload)
                    if operation == 0x02:
                        if not self.client_is_chatting:  # SYN
                            self.default_daemons.append((payload, 7777))
                            self.send_message_to_daemons(datagram_type, operation, user, payload)
                        else:
                            self.send_message_to_daemons(datagram_type, operation, user, payload)
                    elif operation == 0x04:
                        self.send_ack(self.last_syn_recv)
                    elif operation == 0x08:
                        if not self.client_is_chatting and address not in self.daemons.values():
                            print("User declined the chat invitatiton")
                            self.send_message_to_daemons(datagram_type, operation, user, payload)
                        elif not self.client_is_chatting:
                            self.send_message_to_daemons(datagram_type, operation, user, payload)
                            time.sleep(2)
                            print(f"User {self.client_username} disconnected from the server")
                            self.client_address = None
                            self.daemons = {}  
                            self.client_username = None  
                            self.last_ack_recv = 0x00
                            self.last_ack_sent = 0x00
                            self.last_syn_sent = 0x00
                            self.last_syn_recv = 0x00
                            self.client_is_chatting = False
                        else:
                            self.send_message_to_daemons(datagram_type, operation, user, payload)
                            print(f"User {self.client_username} left the chat")
                            self.daemons = {}  
                            self.last_ack_recv = 0x00
                            self.last_ack_sent = 0x00
                            self.last_syn_sent = 0x00
                            self.last_syn_recv = 0x00
                            self.client_is_chatting = False



                elif datagram_type == 0x02:
                    # Broadcast the client's message to all other daemons
                    print(f"From client: {payload}")
                    self.send_message_to_daemons(0x01, 0x02, self.client_username, payload)
            except ConnectionResetError as e:
                print(f"Connection reset error: {e}")
                break
            except OSError as e:
                print(f"OS error: {e}")
                break


    def start(self):
        """Start the daemon to handle client and daemon messages."""
        print(f"Daemon started. Listening on {self.daemon_address} for daemons and on port 7778 for clients.")

        # Start the daemon message handling in a separate thread
        threading.Thread(target=self.handle_daemon_messages, daemon=True).start()

        # Start the client message handling in the main thread
        self.handle_client_messages()


if __name__ == "__main__":
    host = "127.0.0.1"
    if len(sys.argv) > 1:
        host = sys.argv[1]
    daemon = UdpDaemon(host)
    daemon.start()
