import socket

def main():
    daemon_ip = input("Enter the daemon IP to connect to: ").strip()
    daemon_port = 7778  # Client-to-daemon UDP port

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        print("Connecting to daemon...")

        # Send an initial handshake to the daemon
        client_socket.sendto(b"HELLO", (daemon_ip, daemon_port))

        # Wait for the daemon's initial message
        response, _ = client_socket.recvfrom(1024)
        print(response.decode('utf-8'), end='')

        # Enter and send the name
        name = input()
        client_socket.sendto(name.encode(), (daemon_ip, daemon_port))

        while True:
            # Enter and send a message
            message = input("Enter your message: ")
            client_socket.sendto(message.encode(), (daemon_ip, daemon_port))
            print("Message sent to daemon. Waiting for replies...\n")

            # Receive and display the reply
            reply, _ = client_socket.recvfrom(1024)
            print(reply.decode('utf-8'))

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()


if __name__ == "__main__":
    main()
