import socket
import ssl
import os

# This is the server program for the client-server communication using SSL.
# The server will authenticate the client using a username and password, currently hardcoded.
# The server will then receive a message from the client and respond with a message of its own.
# Then close the connection.

# Goals: Implement a file transfer system using TCP and SSL. The server should wait for user input
# to receive commands to either send or receive files.



# //////////////// Server setup and connection process ////////////////
# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Define the server address and port
HOST = '127.0.0.1'
PORT = 10615

# Load Server-side SSL context. The server loads its own certificate and private key. The client will load the
# server's cert to verify the server's identity.
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")

# Bind the socket to the defined address and port
server_socket.bind((HOST, PORT))

# Hardcoded Authentication Credentials, temporary database
USER_DATABASE = {
    "Pierre": "password123",
    "admin": "password",
    "guest": "guest"
}

# Listen for incoming connections
server_socket.listen()
print(f"Listening for connections on {HOST}:{PORT}")

# Accept a connection when found
client_socket, client_address = server_socket.accept()
print(f"Connection from {client_address} has been established!")

# Wrap the client socket with SSL
ssl_client_socket = context.wrap_socket(client_socket, server_side=True)
# //////////////// Server setup and connection process ////////////////



# //////////////// Authentication process ////////////////
authenticated = False
current_user = None  # Track the current user

while not authenticated:
    ssl_client_socket.send("Username: ".encode())
    username = ssl_client_socket.recv(1024).decode().strip()

    ssl_client_socket.send("Password: ".encode())
    password = ssl_client_socket.recv(1024).decode().strip()

    # Check if the username and password are in the database
    if USER_DATABASE.get(username) == password:
        ssl_client_socket.send("You are authenticated!".encode())
        authenticated = True
        current_user = username
        user_folder = os.path.join("ServerFiles", current_user)
        os.makedirs(user_folder, exist_ok=True) # Check that the folder exists, if not create it
    else:
        ssl_client_socket.send("Invalid credentials! Try again".encode())
# //////////////// Authentication process ////////////////



# //////////////// Command processing ////////////////
print("Connection established with user:", current_user)
print("Waiting for commands...")
while True:
    command = ssl_client_socket.recv(1024).decode().strip()
    print(f"Received command: {command}")

    if command.lower() == "exit":
        print("Client closed the connection.")
        break

    if command.startswith("upload"):
        # Extract filename
        filename = command.split()[1]
        file_size = int(ssl_client_socket.recv(1024).decode())
        ssl_client_socket.send(b"ACK")  # Acknowledge the file size

        # Receive the file
        file_path = os.path.join(user_folder, filename)
        with open(file_path, "wb") as file:
            received = 0
            while received < file_size:
                data = ssl_client_socket.recv(1024)
                file.write(data)
                received += len(data)
        print(f"File {filename} received successfully!")

    elif command.startswith("download"):
        # Extract filename
        filename = command.split()[1]
        file_path = os.path.join(user_folder, filename)
        if os.path.exists(file_path):
            # Send the file size
            file_size = os.path.getsize(file_path)
            ssl_client_socket.send(str(file_size).encode())
            ssl_client_socket.recv(1024) # Wait for the client to acknowledge the file size

            # Send the file
            with open(file_path, "rb") as file:
                for data in file:
                    ssl_client_socket.send(data)
            print(f"File {filename} sent successfully!")
        else:
            ssl_client_socket.send("File not found!".encode())

    elif command.lower() == "list":
        # Send the list of files in the user's folder
        files = os.listdir(user_folder)
        file_list = "\n".join(files)
        ssl_client_socket.send(file_list.encode())
# ////////////////// Command processing ////////////////



# Close the SSL-wrapped client socket
ssl_client_socket.close()

# Close the server
server_socket.close()

# Run the server and client scripts in separate terminal windows.
# The server script should be run first.
