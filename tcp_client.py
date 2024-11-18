import socket
import ssl
import os

# This is the client program for the client-server communication using SSL.
# The client should send authentication credentials, which are currently hardcoded.
# The client will then send a message to the server and receive a response.
# Then close the connection.

# Goals: 
# 
#   X Implement a file transfer system using TCP and SSL. The server should wait for user input
#   to receive commands to either send or receive files. Implement a client that can send commands,
#   waiting for user input.



# //////////////// Client setup and connection process ////////////////
# Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Define the server address and port
HOST = '127.0.0.1'
PORT = 10615

# Load Client-side SSL context. The client will load the server's certificate to verify the server's identity.
context = ssl.create_default_context()
context.load_verify_locations("server.crt")

# Wrap the socket with SSL to connect to the server
ssl_client_socket = context.wrap_socket(client_socket, server_hostname="Pierre")

# Connect to the server
print(f"Connecting to {HOST} on port {PORT}")
ssl_client_socket.connect((HOST, PORT))
# //////////////// Client setup and connection process ////////////////



# //////////////// Authentication process ////////////////
authenticated = False

while not authenticated:
    # Receive the server's authentication request
    usernamePrompt = ssl_client_socket.recv(1024).decode()
    print(usernamePrompt, end="")
    username = input()
    ssl_client_socket.send(username.encode())

    # Receive the server's password request
    passwordPrompt = ssl_client_socket.recv(1024).decode()
    print(passwordPrompt, end="")
    password = input()
    ssl_client_socket.send(password.encode())

    # Check if the authentication was successful
    authResult = ssl_client_socket.recv(1024).decode()
    if "You are authenticated" in authResult:
        print(authResult)
        authenticated = True
    else:
        print("Authentication failed!")
# //////////////// Authentication process ////////////////



# //////////////// Command processing ////////////////
print("Connection established! Type 'exit' to close the connection.")
while True:
    command = input("Enter a command (upload <filename> | download <filename> | delete <filename> | manage | list | exit): ")
    ssl_client_socket.send(command.encode())

    if command.lower() == "exit":
        print("Closing the connection")
        break

    elif command.startswith("upload"):
        filename = command.split()[1]
        if os.path.exists(filename):
            file_size = os.path.getsize(filename)
            ssl_client_socket.send(str(file_size).encode())
            ssl_client_socket.recv(1024)  # Wait for the server to acknowledge

            with open(filename, "rb") as file:
                for data in file:
                    ssl_client_socket.send(data)
            print(f"File {filename} sent successfully!")
        else:
            print("File not found!")

    elif command.startswith("download"):
        filename = command.split()[1]

        # Send the filename to the server
        ssl_client_socket.send(filename.encode())

        # Receive the file size or error message
        response = ssl_client_socket.recv(1024).decode()
        if "File not found" in response:
            print(response)
            continue
        else:
            # Acknowledge the file size
            file_size = int(response)
            ssl_client_socket.send(b"SIZE RECEIVED")

        # Receive the file
        with open(filename, "wb") as file:
            received = 0
            while received < file_size:
                data = ssl_client_socket.recv(1024)
                file.write(data)
                received += len(data)
            print(f"File {filename} received successfully!")

    elif command.lower() == "list":
        # Receive the list of files from the server
        file_list = ssl_client_socket.recv(1024).decode()
        print(f"Your files:\n{file_list}")

    elif command.startswith("delete"):
        filename = command.split()[1]
        ssl_client_socket.send(filename.encode())
        response = ssl_client_socket.recv(1024).decode()
        print(response)
    
    elif command.lower() == "manage":
        response = ssl_client_socket.recv(1024).decode()
        print(response)
# //////////////// Command processing ////////////////



# Close the connection
ssl_client_socket.close()
