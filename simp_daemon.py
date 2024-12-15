import socket
import threading

DAEMON_PORT = 7777  # Port for daemon-to-daemon communication
CLIENT_PORT = 7778  # Port for client-to-daemon communication

def handle_client(daemon_socket, client_address, peer_daemons):
    """Handle messages from a connected client."""
    print(f"New client connected: {client_address}")

    # Send initial prompt to client
    daemon_socket.sendto(b"Enter your name: ", client_address)
    try:
        # Receive the client's name
        client_name, _ = daemon_socket.recvfrom(1024)
        client_name = client_name.decode('utf-8').strip()

        daemon_socket.sendto(b"You can now send messages.\n", client_address)

        while True:
            # Receive a message from the client
            message, _ = daemon_socket.recvfrom(1024)
            message = message.decode('utf-8').strip()

            if not message:
                continue  # Ignore empty messages

            full_message = f"From {client_name}: {message}"
            print(f"Received from {client_name}: {message}")

            # Forward the message to all peer daemons
            for peer_ip in peer_daemons:
                daemon_socket.sendto(full_message.encode('utf-8'), (peer_ip, DAEMON_PORT))
    except Exception as e:
        print(f"Error handling client {client_address}: {e}")


def handle_daemon(daemon_socket, connected_clients):
    """Handle messages received from other daemons."""
    while True:
        try:
            # Receive message from another daemon
            message, addr = daemon_socket.recvfrom(1024)
            decoded_message = message.decode('utf-8')

            print(f"Received message from daemon {addr}: {decoded_message}")

            # Relay the message to all connected clients
            for client_address in connected_clients:
                try:
                    daemon_socket.sendto(f"{decoded_message}\n".encode('utf-8'), client_address)
                except Exception as e:
                    print(f"Error sending to client {client_address}: {e}")
        except Exception as e:
            print(f"Daemon communication error: {e}")
            break


def start_daemon(my_ip, peer_daemons):
    """Start the daemon."""
    daemon_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind the daemon to the ports for both client and daemon communication
    daemon_socket.bind((my_ip, CLIENT_PORT))

    print(f"Daemon running on {my_ip}. Waiting for connections...")

    # List to keep track of connected clients
    connected_clients = []

    # Start a thread to handle daemon-to-daemon communication
    threading.Thread(target=handle_daemon, args=(daemon_socket, connected_clients), daemon=True).start()

    while True:
        # Receive data from either a client or another daemon
        try:
            message, address = daemon_socket.recvfrom(1024)

            # If the message is from a client (port 7778), start a new thread to handle it
            if address[1] == CLIENT_PORT:
                if address not in connected_clients:
                    connected_clients.append(address)
                threading.Thread(target=handle_client, args=(daemon_socket, address, peer_daemons)).start()

        except Exception as e:
            print(f"Error receiving message: {e}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python daemon.py <my_ip> <peer_daemon_ip_1> [<peer_daemon_ip_2> ...]")
        sys.exit(1)

    my_ip = sys.argv[1]
    peer_daemons = sys.argv[2:]  # List of peer daemon IPs

    start_daemon(my_ip, peer_daemons)
