import socket
import ssl
import os
import hashlib
import logging

# This is the server program for the client-server communication using SSL.
# The server will authenticate the client using a username and password, currently hardcoded.
# The server will then receive a message from the client and respond with a message of its own.
# Then close the connection.

# Notes:
#   
#   Uploading and Downloading for admins and non-admins work now. Filepaths entered into the client are relative to the user's folder.
#   Admins can access other folders with "../" in the filepath, but non-admins cannot. Uploads still upload to user's folder.
#
#   Resolved empty commands and malformed commands. Invalid commands are now handled better.
#
# Goals: 
#   X Implement a file transfer system using TCP and SSL. The server should wait for user input
#   to receive commands to either send or receive files.
#    
#   X Implement some kind of RBAC. Users and admins with different permissions/actions.
#
#   X Implement usage of stored hashed credentials. Compare to user-given credentials (to be hashed by server).
#
#   X Implement a logging/audit system
#
#   Implement brute-force protection. Lockout after x failed attempts.
#   Create 'shared' directory that any user can upload/download to. Only admins should be able to delete/manage
#   Consider what the 'manage' command should do. maybe change permissions.
#   Possibly add a guest role with limited permisions. (Only list?)
#   Implement a SQL database to handle stored authentication credentials (yes) and roles (maybe)

# //////////////////////// Logging //////////////////////////////////
logging.basicConfig(filename="ServerFiles/admin/server.log", level=logging.INFO, format="%(asctime)s - %(message)s")
# //////////////////////// Logging //////////////////////////////////


# ///////////////// Authentication Process /////////////////////////

# Function to load credentials from data source, currently "pwd.txt"
def load_credentials(file_path="ServerFiles/admin/pwd.txt"):
    credentials = {} # passwords
    roles = {} # roles
    with open(file_path, "r") as file:
        for line in file:
            username, hashed_password, role = line.strip().split(":")
            credentials[username] = hashed_password
            roles[username] = role
    logging.info("Credentials loaded from %s", file_path)
    return credentials, roles

# Function to hash a password, uses SHA256, same as stored credentials
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def authenticate(username, password, credentials):
    password_hash = hash_password(password)
    if username in credentials and credentials[username] == password_hash:
        logging.info("User %s authenticated successfully", username)
        return True
    else:
        logging.warning("Failed authentication attempt for user %s", username)
        return False

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
HOST = '0.0.0.0'
PORT = 10615

# Load Server-side SSL context. The server loads its own certificate and private key. The client will load the
# server's cert to verify the server's identity.
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="ServerFiles/admin/server.crt", keyfile="ServerFiles/admin/server.key")

# Bind the socket to the defined address and port
server_socket.bind((HOST, PORT))

# Listen for incoming connections
server_socket.listen()
print(f"Listening for connections on {HOST}:{PORT}")
logging.info("Server started and listening on %s:%s", HOST, PORT)

# Load Credentials and Roles
CREDENTIALS, ROLES = load_credentials()

# Accept connections continuously
while True:
    try:
        # Accept a connection
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address} has been established!")
        logging.info("Connection established with %s", client_address)

        # Attempt to wrap the client socket with SSL
        try:
            ssl_client_socket = context.wrap_socket(client_socket, server_side=True)
            logging.info("Secure connection established with %s", client_address)
        except ssl.SSLError as e:
            logging.warning("SSL error with %s: %s", client_address, e)
            client_socket.close()
            continue
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
            if authenticate(username, password, CREDENTIALS):
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

            # Validate the command
            if not command:
                ssl_client_socket.send(b"Invalid Command: Command is empty.")
                logging.warning("Empty command received from %s", current_user)
                command = None
                continue

            # Split and extract the action
            try:
                action = command.split()[0]
            except IndexError:
                ssl_client_socket.send(b"Invalid Command: Unable to parse action.")
                logging.warning("Malformed command received from %s: %s", current_user, command)
                continue

            print(f"Received command: {command}")
            logging.info("Received command: %s from %s", command, current_user)

            # The connection between client-server is closed
            if command.lower() == "exit":
                print("Client closed the connection.")
                logging.info("Client %s closed the connection", current_user)
                break


            # The client intends to upload a file to their respective directory
            if action == "upload":
                # Extract filename
                filename = command.split()[1]

                # Receive the file size    
                file_size = int(ssl_client_socket.recv(1024).decode())
                ssl_client_socket.send(b"ACK")  # Acknowledge the file size

                    # Receive the file
                file_path = os.path.join(user_folder, filename)

                if os.path.exists(file_path):
                    ssl_client_socket.send(b"File already exists!")
                    logging.warning("File %s already exists for user %s", filename, current_user)
                    continue

                with open(file_path, "wb") as file:
                    received = 0
                    while received < file_size:
                        data = ssl_client_socket.recv(1024)
                        file.write(data)
                        received += len(data)
                print(f"File {filename} received successfully!")
                logging.info("File %s received successfully from %s", filename, current_user)

            # The client intends to download a file from their respective directory 
            elif action == "download":

                # Validate and construct the full file path
                relative_path = command.split()[1] # User-specified path
                full_path = os.path.abspath(os.path.join(user_folder, relative_path))

                # Ensure the path is within the user's folder
                if not current_role == "admin" and not full_path.startswith(os.path.abspath(user_folder)):
                    ssl_client_socket.send(b"Invalid Command: Unauthorized file access attempt.")
                    logging.warning("Unauthorized file access attempt by %s: %s", current_user, relative_path)
                    continue

                # Check if the file exists for admins and non-admins
                if os.path.exists(full_path) and os.path.isfile(full_path):
                    # Send the file size
                    file_size = os.path.getsize(full_path)
                    ssl_client_socket.send(str(file_size).encode())
                    ssl_client_socket.recv(1024) # Wait for the client to acknowledge the file size

                    # Send the file
                    with open(full_path, "rb") as file:
                        for data in file:
                            ssl_client_socket.send(data)
                    print(f"File {relative_path} sent successfully!")
                    logging.info("File %s sent successfully to %s", relative_path, current_user)
                else:
                    ssl_client_socket.send("File not found!".encode())
                    logging.warning("File %s not found for user %s", relative_path, current_user)

            # The client intends to list the files in their respective directory
            elif action ==  "list":
                # Send the list of files in the user's folder
                files = os.listdir(user_folder)

                if files:
                    file_list = "\n".join(files)
                    ssl_client_socket.send(file_list.encode())
                    logging.info("List of files sent to %s", current_user)
                else:
                    ssl_client_socket.send(b"No files in your directory.")
                    logging.info("No files in directory for %s", current_user)

            # The client is an admin who intends to delete a specific file in their (for now only their) directory
            elif action == "delete":
                if current_role == "admin":
                    logging.info("User %s with admin role requested to delete a file", current_user)

                    # Check if a filename parameter was provided
                    parts = command.split(maxsplit=1)
                    if len(parts) < 2:  # If there is no second part, the filename is missing
                        ssl_client_socket.send(b"Invalid Command: Missing filename. Usage: delete <filename>")
                        logging.warning("Invalid delete command by %s: Missing filename", current_user)
                        continue
                    filename = parts[1]
                    file_path = os.path.join(f"ServerFiles/{current_user}", filename)

                    if os.path.exists(file_path):
                        os.remove(file_path)
                        ssl_client_socket.send(f"File '{filename}' deleted successfully.".encode())
                        logging.info("File %s deleted successfully", filename)
                    else:
                        ssl_client_socket.send(b"File not found!")
                        logging.warning("File %s not found for deletion", filename)

                # Denied Access
                else:
                    ssl_client_socket.send(b"Access Denied: You do not have permission for this action")
                    logging.warning("User %s attempted an unauthorized action", current_user)
                
            # Management action to be implemented later
            elif action == "manage":
                if current_role == "admin":
                    logging.info("User %s with admin role requested to manage files", current_user)
                    ssl_client_socket.send(b"Admin Management Feature Coming Soon")

                # Denied Access
                else:
                    ssl_client_socket.send(b"Access Denied: You do not have permission for this action")
                    logging.warning("User %s attempted an unauthorized action", current_user)
        # Command Invalid
            else:
                ssl_client_socket.send(b"Invalid Command. Try again.")
                logging.info("User %s attempted an invalid command", current_user)
        # ////////////////// Command processing ////////////////
    except Exception as e:
        logging.error("An error occurred: %s", e)
    finally: 
        # Close the client socket if it's open
        if 'ssl_client_socket' in locals() and ssl_client_socket:
            ssl_client_socket.close()
            logging.info("Connection with %s closed", client_address)


    # Close the SSL-wrapped client socket after exit by client
    ssl_client_socket.close()
    logging.info("Connection with %s closed", current_user)

    # Close the server
    server_socket.close()
    logging.info("Server closed")

    # Run the server and client scripts in separate terminal windows.
    # The server script should be run first.
