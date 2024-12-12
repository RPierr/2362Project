import socket
import ssl

# Server connection details
HOST = "172.212.203.54"  # Server IP address
PORT = 10615        # port number

# Number of commands to send
NUM_COMMANDS = 350000 # DOS achieved at 211864, mitigate with rate-limiting

# Create SSL context (same as in tcp_client.py)
context = ssl.create_default_context()
context.load_verify_locations("server.crt")  # Load the server's certificate for verification

# Connect to the server
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        with context.wrap_socket(client_socket, server_hostname="Pierre") as ssl_client_socket:
            ssl_client_socket.connect((HOST, PORT))
            print(f"Connected to {HOST}:{PORT}")

            # Flood the server with commands
            for i in range(NUM_COMMANDS):
                try:
                    # Example command (use a valid or invalid command for testing)
                    command = f"upload test_file_{i}.txt"
                    ssl_client_socket.send(command.encode())

                    # Optional: Wait for server response
                    response = ssl_client_socket.recv(1024).decode()
                    print(f"Server response for command {i}: {response}")

                except Exception as e:
                    print(f"Error sending command {i}: {e}")
                    break

            print("Flood test completed.")
            # the connection will be closed automatically when exiting the 'with' block. EOF
            # will be sent to the server to indicate the end of the connection. 

except Exception as e:
    print(f"Connection failed: {e}")
