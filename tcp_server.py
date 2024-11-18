import socket
import ssl
import os
import hashlib

# This is the server program for the client-server communication using SSL.
# The server will authenticate the client using a username and password, currently hardcoded.
# The server will then receive a message from the client and respond with a message of its own.
# Then close the connection.

# Goals: 
#   X Implement a file transfer system using TCP and SSL. The server should wait for user input
#   to receive commands to either send or receive files.
#    
#   X Implement some kind of RBAC. Users and admins with different permissions/actions.
#
#   X Implement usage of stored hashed credentials. Compare to user-given credentials (to be hashed by server).
#
#   Create 'shared' directory that any user can upload/download to. Only admins should be able to delete/manage
#   Consider what the 'manage' command should do
#   Possibly add a guest role with limited permisions. (Only list?)
#   Implement a logging/audit system
#   Implement a SQL database to handle stored authentication credentials (yes) and roles (maybe)


# ///////////////// Authentication Process /////////////////////////

# Function to load credentials from data source, currently "pwd.txt"
def load_credentials(file_path="pwd.txt"):
    credentials = {} # passwords
    roles = {} # roles
    with open(file_path, "r") as file:
        for line in file:
            username, hashed_password, role = line.strip().split(":")
            credentials[username] = hashed_password
            roles[username] = role
    
    return credentials, roles

# Function to hash a password, uses SHA256, same as stored credentials
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Dictionary of Role-based Permissions
ROLE_PERMISSIONS = {
    "admin" : {"upload", "download", "list", "delete", "manage"},
    "user" : {"upload", "download", "list"}
    }
# ///////////////// Authentication Process /////////////////////////



# //////////////// Server setup and connection process ////////////////
# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Define the server address and port. Arbritray 
HOST = '127.0.0.1'
PORT = 10615

# Load Server-side SSL context. The server loads its own certificate and private key. The client will load the
# server's cert to verify the server's identity.
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")

# Bind the socket to the defined address and port
server_socket.bind((HOST, PORT))

# Listen for incoming connections
server_socket.listen()
print(f"Listening for connections on {HOST}:{PORT}")

# Load Credentials and Roles
CREDENTIALS, ROLES = load_credentials()

# Accept a connection when found
client_socket, client_address = server_socket.accept()
print(f"Connection from {client_address} has been established!")

# Wrap the client socket with SSL
ssl_client_socket = context.wrap_socket(client_socket, server_side=True)
# //////////////// Server setup and connection process ////////////////



# //////////////// Authentication process ////////////////
authenticated = False
current_user = None  # Track the current user
current_role = None # Role

while not authenticated:
    ssl_client_socket.send("Username: ".encode())
    username = ssl_client_socket.recv(1024).decode().strip()

    ssl_client_socket.send("Password: ".encode())
    password = ssl_client_socket.recv(1024).decode().strip()
    hashed_password = hash_password(password) # Hash the password

    # Check if the username and password are in the database
    if username in CREDENTIALS and CREDENTIALS[username] == hashed_password:
        ssl_client_socket.send("You are authenticated!".encode())
        authenticated = True
        current_user = username
        current_role = ROLES[username]
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
    action = command.split()[0]
    print(f"Received command: {command}")

    # The connection between client-server is closed
    if command.lower() == "exit":
        print("Client closed the connection.")
        break

    # Check role permissions to following commands

    if action in ROLE_PERMISSIONS[current_role]:

        # The client intends to upload a file to their respective directory
        if action == "upload":
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

        # The client intends to download a file from their respective directory 
        elif action == "download":
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

        # The client intends to list the files in their respective directory
        elif action ==  "list":
            # Send the list of files in the user's folder
            files = os.listdir(user_folder)

            if files:
                file_list = "\n".join(files)
                ssl_client_socket.send(file_list.encode())
            else:
                ssl_client_socket.send(b"No files in your directory.")

        # The client is an admin who intends to delete a specific file in their (for now only their) directory
        elif action == "delete" and current_role == "admin":
            filename = command.split()[1]
            file_path = os.path.join(f"ServerFiles/{current_user}", filename)

            if os.path.exists(file_path):
                os.remove(file_path)
                ssl_client_socket.send(f"File '{filename}' deleted successfully.".encode())
            else:
                ssl_client_socket.send(b"ERROR: File not found.")
        
        # Management action to be implemented later
        elif action == "manage" and current_role == "admin":
            
            ssl_client_socket.send(b"Admin Management Feature Coming Soon")

        # Denied Access
        else:
            ssl_client_socket.send(b"Access Denied: You do not have permission for this action")
    # Command Invalid
    else:
        ssl_client_socket.send(b"Invalid Command. Try again.")
# ////////////////// Command processing ////////////////



# Close the SSL-wrapped client socket
ssl_client_socket.close()

# Close the server
server_socket.close()

# Run the server and client scripts in separate terminal windows.
# The server script should be run first.
