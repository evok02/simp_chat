import socket
import threading
import struct
import sys
import time
from datetime import datetime

class UdpDaemon:
    def __init__(self, host):
        self.daemon_address = (host, 7777)  # Daemon-to-daemon communication on port 7777
        self.client_address = None  # To store the connected client address (port 7778)
        self.daemons = {}  # Known daemons (address: (host, port))
        self.client_username = None  # Username of the connected client
        self.last_ack_recv = 0x00
        self.last_ack_sent = 0x00
        self.last_syn_sent = 0x00
        self.last_syn_recv = 0x00
        self.client_is_chatting = False
        self.timeout = 5
        self.ack_received_event = threading.Event()
        self.syn_buffer = {}

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

    def send_message_to_daemons(self, datagram_type, operation, username, message):
        """Send a message with username to all known daemons."""
        if datagram_type == 0x01 and operation == 0x02:
            
            if len(self.daemons.values()) == 0:
                formatted_message = f'Conversation request is pending...\nDo you want to accept chat with {username}'
                if self.last_syn_sent == 0x00:
                    datagram = self.create_datagram(0x01, 0x02, 0x01, username, formatted_message)
                else:
                    datagram = self.create_datagram(0x01, 0x02, 0x00, username, formatted_message)
                self.daemon_sock.sendto(datagram, (message, 7777))
            else:
                self.send_syn(message)

        if datagram_type == 0x01 and operation == 0x04:
            formatted_message = ""
            datagram = self.create_datagram(0x01, 0x04, self.last_syn_recv, username, formatted_message)
            for address in self.daemons.values():
                self.daemon_sock.sendto(datagram, address)
            self.last_ack_sent = self.last_syn_recv
        if datagram_type == 0x01 and operation == 0x08:
            formatted_message = f"{username} declined the connection"
            datagram = self.create_datagram(0x01, 0x08, 0, username, formatted_message)
            for address in self.daemons.values():
                self.daemon_sock.sendto(datagram, address)
        else:
            formatted_message = f"{username}: {message}"
            datagram = self.create_datagram(0x02, 0x01, 0, username, formatted_message)
            for address in self.daemons.values():
                self.daemon_sock.sendto(datagram, address)

    def send_ack(self, sequence):
        """Send ACK for a received SYN."""
        try:
            datagram = self.create_datagram(0x01, 0x04, sequence, "Server", "")
            for address in self.daemons.values():
                self.daemon_sock.sendto(datagram, address)
            self.last_ack_sent = sequence
        except:
            print("Can't send the ACK")

    def send_syn(self, message = ""):
        """ Send SYN """
        try:
            sequence = 0x01 if self.last_syn_sent == 0x00 else 0x00
            datagram = self.create_datagram(0x01, 0x02, sequence, self.client_username, message)
            print(self.client_username)
            self.syn_buffer[sequence] = (datagram, time.time())
            for address in self.daemons.values():
                self.daemon_sock.sendto(datagram, address)
            self.last_syn_sent = sequence
            print(f"SYN sent {sequence}")
        except Exception as e:
            print(f"Can't send the SYN {sequence}: {e}")
    
    def retransmit_syns(self):
        """Check for unacknowledged SYNs and retransmit if necessary."""
        current_time = time.time()
        for sequence, (datagram, timestamp) in list(self.syn_buffer.items()):
            if current_time - timestamp > self.timeout:
                print(f"Retransmitting SYN with sequence {sequence}")
                for address in self.daemons.values():
                    self.daemon_sock.sendto(datagram, address)
                self.syn_buffer[sequence] = (datagram, current_time)




    def forward_to_client(self, message):
        """Forward a message to the connected client."""
        if self.client_address:
            datagram = self.create_datagram(0x02, 0x01, 0x00, self.client_username, message)
            self.client_sock.sendto(datagram, self.client_address)

    def handle_daemon_messages(self):
        """Handle messages from other daemons."""
        while True:
            try:
                data, address = self.daemon_sock.recvfrom(1024)
                datagram_type, operation, sequence, user, length, payload = self.parse_datagram(data)
                
                current_time = datetime.now().strftime("%H:%M:%S")
                # Add sender to known daemons if new
                if address not in self.daemons.values() and address != self.daemon_address:
                    self.daemons[address] = address
                    print(f"Added new daemon: {address}")
                
                if datagram_type == 0x01:
                    if operation == 0x02 and not self.client_is_chatting:
                        print(f"Daemon received a SYN {sequence}")
                        self.last_syn_recv = sequence
                        self.forward_to_client(payload)
                    if operation == 0x02 and self.client_is_chatting :
                        print(f"Received SYN: {payload}, {current_time}")
                        self.send_ack(sequence)
                        self.forward_to_client(payload)
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
                            self.client_sock.sendto(datagram, self.client_address)
                        else:
                            self.forward_to_client("User left chat")

                # Forward the message to the client
                elif datagram_type == 0x02:  # Chat message
                    self.forward_to_client(payload)
            except ConnectionResetError as e:
                print(f"Connection reset error: {e}")
                break
            except OSError as e:
                print(f"OS error: {e}")
                break
            except Exception as e:
                print(f"Error in handle daemon messages {e}")
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
                    if operation == 0x02:
                        if not self.client_is_chatting:  # SYN
                            self.default_daemons.append((payload, 7777))
                            self.send_message_to_daemons(datagram_type, operation, user, payload)
                        else:
                            self.send_message_to_daemons(datagram_type, operation, user, payload)
                    elif operation == 0x04:
                        self.send_ack(self.last_syn_recv)
                    elif operation == 0x08:
                        if not self.client_is_chatting:
                            print("User declined the chat invitatiton")
                            self.send_message_to_daemons(datagram_type, operation, user, payload)
                        else:
                            print(f"User {self.client_username} disconnected from the server")
                            self.client_address = None
                            self.daemons = {}  
                            self.client_username = None  
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
        print(f"Daemon started. Listening on {self.daemon_address} for daemons.")
        print("Listening on port 7778 for client connections.")

        # Start separate threads for daemon and client communication
        threading.Thread(target=self.handle_daemon_messages, daemon=True).start()
        threading.Thread(target=self.handle_client_messages, daemon=True).start()

        while True:
            time.sleep(self.timeout)
            self.retransmit_syns()

if __name__ == "__main__":
    host = sys.argv[1]
    daemon = UdpDaemon(host)
    daemon.start()

#192.168.1.20