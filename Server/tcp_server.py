import socket
import ssl
import os
import hashlib
import logging
import threading
import sys
import signal

"""
 This is the server program for the client-server communication using SSL.
 The server will authenticate the client using a username and password, currently hardcoded.
 The server will then receive a message from the client and respond with a message of its own.
 Then close the connection.
 Kind of broke the command processing functions. Will fix later.


 Notes:
   
   Uploading and Downloading for admins and non-admins work now. Filepaths entered into the client are relative to the user's folder.
   Admins can access other folders with "../" in the filepath, but non-admins cannot. Uploads still upload to user's folder.

   Resolved empty commands and malformed commands. Invalid commands are now handled better.

   
 Goals: 
   X Implement a file transfer system using TCP and SSL. The server should wait for user input
   to receive commands to either send or receive files.
    
   X Implement some kind of RBAC. Users and admins with different permissions/actions.

   X Implement usage of stored hashed credentials. Compare to user-given credentials (to be hashed by server).

   X Implement a logging/audit system

   X Network the application. Get public IP address (Azure VM) and test client-server communication.

   X Use multiple clients to test the server's ability to handle multiple connections. (multi-threading)

   X Modularlize the code. Separate the authentication, command processing, and connection handling into functions.
   
   X Gracefully shutdown the server. Either by sending a command or by using a signal handler.

   Revamp logging. Include timestamps, IPs, and other relevant information.
   Improve multi-threading. Add socket timeouts, optimize logging, limit threads.
   Add more commands: Move, Rename, Copy, etc.
   Allow clients create new login credentials. (Admins only?)
   Implement brute-force protection. Lockout after x failed attempts.
   Create 'shared' directory that any user can upload/download to. Only admins should be able to delete/manage.
   Consider what the 'manage' command should do. maybe change a user's permissions.
   Possibly add a guest role with limited permisions. (Only list?)
   Implement a SQL database to handle stored authentication credentials (yes) and roles. (maybe)
   Implement rate-limiting to prevent DoS attacks.
   Utilize ftp or sftp instead of custom file transfer system. Use port 21 or 22. No more cusotm port.

 Longer-term Goals:
   Implement a firewall to block malicious IPs.
   Implement a web interface for the server. (maybe)
   Implement a GUI for the client. (maybe)
   Implement a file explorer for the client. (maybe)
   Implement a file editor for the client. (maybe)
   Look into purchasing SSL certificate from a CA.
"""


# Function to load credentials from data source, currently "pwd.txt"
def load_credentials(file_path="ServerFiles/admin/pwd.txt"):
    """
    Loads the credentials from the specified file. Simulates a database temporarily.

    :param file_path: The path to the file containing the credentials
    :return: A tuple containing the credentials and roles
    """
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
    """
    Hash the password using SHA256.

    :param password: The password to hash
    :return: The hashed password
    """
    return hashlib.sha256(password.encode()).hexdigest()


# Function to authenticate a user based on username and password
def verify_user(username, password, credentials):
    """
    Check if the user's credentials are valid (exist in database).

    :param username: The username of the user
    :param password: The password of the user
    :param credentials: The dictionary of stored credentials
    :return: True if the user is authenticated, False otherwise
    """
    password_hash = hash_password(password)
    if username in credentials and credentials[username] == password_hash:
        logging.info("User %s authenticated successfully", username)
        return True
    else:
        logging.warning("Failed authentication attempt for user %s", username)
        return False
    

# Function to authenticate the user fully
def authenticate_user(ssl_client_socket):
    """
    Authenticate the user by prompting for a username and password.
    The function will then verify the user's credentials against the stored credentials.

    :param ssl_client_socket: The SSL-wrapped socket object
    :return: The username, role, and user folder if authenticated. None otherwise.
    """

    authenticated = False
    current_user = None  # Track the current user
    current_role = None # Role

    # Load Credentials and Roles
    CREDENTIALS, ROLES = load_credentials()

    while not authenticated:
        
        # Prompt the user for their username and password
        ssl_client_socket.send("Username: ".encode())
        username = ssl_client_socket.recv(1024).decode().strip()

        ssl_client_socket.send("Password: ".encode())
        password = ssl_client_socket.recv(1024).decode().strip()
        hashed_password = hash_password(password) # Hash password for comparison

        # Check if the username and password are in the database
        if verify_user(username, password, CREDENTIALS):
            ssl_client_socket.send("You are authenticated!".encode())
            authenticated = True
            current_role = ROLES[username]
            current_user = username
            user_folder = os.path.join("ServerFiles", current_user)
            os.makedirs(user_folder, exist_ok=True)
            return current_user, current_role, user_folder
        else:
            ssl_client_socket.send("Invalid credentials! Try again".encode())
            

# Function to check permissions for a user against a specific action
def check_permissions(role, action):
    """
    Check if the user's role has permission to perform the given action.
    
    :param role: The role of the user (e.g., 'admin', 'user')
    :param action: The action the user wants to perform (e.g., 'upload', 'shutdown')
    :return: True if the user has permission, False otherwise
    """

    if role in ROLE_PERMISSIONS and action in ROLE_PERMISSIONS[role]:
        return True
    return False


# Function to process commands given by the user
def process_command(command, ssl_client_socket, current_user, current_role, current_folder):
    """
    Processes the command given by the user. Extracts the action 
    and parameters from string. Handles error cases and invalid commands.

    :param command: The command given by the user
    :param ssl_client_socket: The SSL-wrapped socket object
    :param current_user: The current user
    :param current_role: The current role of the user
    :param current_folder: The current folder of the user
    """
    if not command:
        ssl_client_socket.send(b"Invalid Command: Command is empty.")
        logging.warning("Empty command received from %s", current_user)
        return
    
    # Split and extract the action
    try:
        action = command.split()[0]
    except IndexError:
        ssl_client_socket.send(b"Invalid Command: Unable to parse action.")
        logging.warning("Malformed command received from %s: %s", current_user, command)
        return
    
    print(f"Received command: {command}")
    logging.info("Received command: %s from %s", command, current_user)

    # Validate command
    valid_commands = {"upload", "download", "list", "delete", "manage", "exit", "shutdown"}
    
    # Check if the action is valid
    if action.lower() not in valid_commands:
        ssl_client_socket.send(b"Invalid Command: Command not recognized.")
        logging.warning("Invalid command received from %s: %s", current_user, command)
        return

    # Check permissions for the action
    if not check_permissions(current_role, action):
        ssl_client_socket.send(b"Permission Denied: You do not have permission to perform this action.")
        logging.warning("Permission denied for %s to perform %s", current_user, action)
        return

    # Exit command
    if action.lower() == "exit":
        print("Client %s closed the connection.", current_user)
        logging.info("Client %s closed the connection", current_user)
        return "exit"
    
    # Shutdown command
    elif action.lower() == "shutdown" and current_role == "admin":
        ssl_client_socket.send(b"Server is shutting down...")
        logging.info("Server shutdown by %s", current_user)
        shutdown_flag.set()
        return "shutdown"
    
    # Handle specific actions/commands
    if action == "upload":
        handle_upload(command, ssl_client_socket, current_user, current_folder)
    elif action == "download":
        handle_download(command, ssl_client_socket, current_user, current_folder)
    elif action == "list":
        handle_list(ssl_client_socket, current_user, current_folder)
    elif action == "delete":
        handle_delete(command, ssl_client_socket, current_user, current_role)
    elif action == "manage":
        handle_manage(ssl_client_socket, current_user)
    else:
        ssl_client_socket.send(b"Invalid Command from %s: Command not recognized.", current_user)
        logging.warning("Invalid command received from %s: %s", current_user, command)


def handle_upload(command, socket, user, folder):
    """
    Handle file uploads from the client.

    :param command: The command given by the client
    :param socket: The SSL-wrapped socket object
    :param user: The current user
    :param folder: The user's folder
    """

    #try:
    filename = command.split()[1]
    #except IndexError:
    #    socket.send(b"Invalid Command: Filename not provided.")
    #    logging.warning("Invalid upload command from %s: Filename not provided", user)
    #    return
    
    # Receive the file size
    try:
        file_size = int(socket.recv(1024).decode())
        socket.send(b"ACK")  # Acknowledge the file size
    except ValueError:
        socket.send(b"Invalid Command: File size not provided.")
        logging.warning("Invalid upload command from %s: File size not provided", user)
        return
    
    # Determine the file path
    file_path = os.path.join(folder, filename)
    print(file_path)

    # Check if the file already exists
    if os.path.exists(file_path):
        socket.send(b"File already exists!")
        logging.warning("File %s already exists for user %s", filename, user)
        return
    
    # Receive the file
    with open(file_path, "wb") as file:
        print(f"Receiving file {filename}...")
        received = 0
        while received < file_size:
            data = socket.recv(1024)
            file.write(data)
            received += len(data)

    # After file is received
    print(f"File {filename} received successfully!")
    logging.info("File %s received successfully from %s", filename, user)
    socket.send(b"File uploaded successfully!")


def handle_download(command, socket, user, folder):
    """
    Handle file downloads from the server.

    :param command: The command given by the client
    :param socket: The SSL-wrapped socket object
    :param user: The current user
    :param folder: The user's folder
    """

    try:
        # Validate and construct the full file path
        relative_path = command.split()[1] # User-specified path
        full_path = os.path.abspath(os.path.join(folder, relative_path))
    except IndexError:
        socket.send(b"Invalid Command: Filename not provided.")
        logging.warning("Invalid download command from %s: Filename not provided", user)
        return
    
    # Ensure the path is within the user's folder
    if not user == "admin" and not full_path.startswith(os.path.abspath(folder)):
        socket.send(b"Invalid Command: Unauthorized file access attempt.")
        logging.warning("Unauthorized file access attempt by %s: %s", user, relative_path)
        return
    
    # Check if the file exists for admins and non-admins
    if os.path.exists(full_path) and os.path.isfile(full_path):
        # Send the file size
        file_size = os.path.getsize(full_path)
        socket.send(str(file_size).encode())
        socket.recv(1024) # Wait for the client to acknowledge the file size

        # Send the file
        with open(full_path, "rb") as file:
            for data in file:
                socket.send(data)
        print(f"File {relative_path} sent successfully!")   
        logging.info("File %s sent successfully to %s", relative_path, user)
    else:
        socket.send("File not found!".encode())
        logging.warning("File %s not found for user %s", relative_path, user)


def handle_list(socket, user, folder):
    """
    Handle listing the files in the user's folder.

    :param socket: The SSL-wrapped socket object
    :param user: The current user
    :param folder: The user's folder
    """

    # Send the list of files in the user's folder
    files = os.listdir(folder)

    if files:
        file_list = "\n".join(files)
        socket.send(file_list.encode())
        logging.info("List of files sent to %s", user)
    else:
        socket.send(b"No files in your directory.")
        logging.info("No files in directory for %s", user)


def handle_delete(command, socket, user, folder):
    """
    Handle file deletion (admin only).

    :param command: The command given by the client
    :param socket: The SSL-wrapped socket object
    :param user: The current user
    :param folder: The user's folder
    """

    # Check if the user is an admin
    if not check_permissions(user, "delete"):
        socket.send(b"Access Denied: You do not have permission for this action")
        logging.warning("User %s attempted an unauthorized action", user)
        return
    else:
        try:
            # Check for filename
            filename = command.split()[1]
        except IndexError:
            socket.send(b"Invalid Command: Missing filename. Usage: delete <filename>")
            logging.warning("Invalid delete command by %s: Missing filename", user)
            return
        
        # Construct the file path
        file_path = os.path.join(folder, filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            socket.send(f"File '{filename}' deleted successfully.".encode())
            logging.info("File %s deleted successfully", filename)
        else:
            socket.send(b"File not found!")
            logging.warning("File %s not found for deletion", filename)

        
def handle_manage(socket, user):
    """
    Handle file management (future command) (admin only).

    :param command: The command given by the client
    :param socket: The SSL-wrapped socket object
    :param user: The current user
    :param folder: The user's folder
    """

    # Check if the user is an admin
    if not check_permissions(user, "manage"):
        socket.send(b"Access Denied: You do not have permission for this action")
        logging.warning("User %s attempted an unauthorized action", user)
        return
    else:
        socket.send(b"Admin Management Feature Coming Soon")
        logging.info("User %s with admin role requested to manage files", user)


# Dictionary of Role-based Permissions
ROLE_PERMISSIONS = {
    "admin" : {"upload", "download", "list", "delete", "manage", "shutdown"},
    "user" : {"upload", "download", "list"}
    }

# Define the server address and port. Arbritray PORT number
HOST = '0.0.0.0'
#HOST = '127.0.0.1'
PORT = 10615
shutdown_flag = threading.Event() # Flag to signal server shutdown
active_threads = [] # List of active threads

# Load Server-side SSL context. The server loads its own certificate and private key. The client will load the
# server's cert to verify the server's identity.
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="ServerFiles/admin/server.crt", keyfile="ServerFiles/admin/server.key")
#context.load_cert_chain(certfile="/workspaces/2362Project/Server/ServerFiles/admin/server.crt", keyfile="/workspaces/2362Project/Server/ServerFiles/admin/server.key")


# Function to handle client connections
def handle_client(client_socket, client_address):
    """
    This function handles the client connection. It authenticates the user, 
    processes commands, and closes the connection.

    :param client_socket: The client socket object
    :param client_address: The client's address (IP, Port)
    """

    # Load the global variable
    global shutdown_flag

    # Attempt to establish a secure connection with the client
    try:

        # Wrap the client socket with SSL
        ssl_client_socket = context.wrap_socket(client_socket, server_side=True)
        logging.info("Secure connection established with %s", client_address)

        # Handling within the client connection
        while True:

            # Authenticate the user once the secure connection is established
            current_user, current_role, user_folder = authenticate_user(ssl_client_socket)

            # Command processing loop
            print("Connection established with user:", current_user)
            print("Waiting for commands...")
            while not shutdown_flag.is_set():

                # Receive the command from the client
                command = ssl_client_socket.recv(1024).decode().strip()

                # Process the command
                result = process_command(command, ssl_client_socket, current_user, current_role, user_folder)
                if result == "exit" or result == "shutdown":
                    break

            # Check for shutdown flag
            if shutdown_flag.is_set():
                break

    # Handle SSL errors
    except ssl.SSLError as e:
        logging.warning("SSL error with %s: %s", client_address, e)
    # Handle socket errors
    except Exception as e:
        logging.error("Error handling client %s: %s", client_address, e)
    # Shutdown flag is set, close connection
    finally:
        logging.info("Closing connection with %s", client_address)
        client_socket.close()


# Signal Handler to shutdown the server
def signal_handler(sig, frame):
    logging.info("Manual server shutdown by signal")
    print("Server is shutting down...")
    shutdown_flag.set()
    sys.exit(0)


# Main Server Loop
def main():
    """
    The main function to start the server and listen for incoming connections. 
    """
    global shutdown_flag
    signal.signal(signal.SIGINT, signal_handler) # Register the signal handler

    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create a socket object
    server_socket.bind((HOST, PORT)) # Bind the socket to the defined address and port
    server_socket.listen(5) # Listen for incoming connections, max 5 connections
    server_socket.settimeout(1) # Set a timeout for the server socket
    print(f"Listening for connections on {HOST}:{PORT}")
    logging.info("Server started and listening on %s:%s", HOST, PORT)

    
    # Accept connections continuously
    # while True:
    try:
        while not shutdown_flag.is_set():
            # Allow connections only if shutown is not signlaed
            try:
                # Accept a connection
                client_socket, client_address = server_socket.accept()
                print(f"Connection from {client_address} has been established!")
                logging.info("Connection established with %s", client_address)

                # Create a new thread to handle the client
                client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
                client_thread.daemon = True # Close the thread when the main program exits
                client_thread.start() # Start the thread
                active_threads.append(client_thread) # Add the thread to the list of active threads
            except socket.timeout:
                continue # Allow loop to continue to check for shutdown flag
    except Exception as e:
        logging.error("An error occurred: %s", e)
    finally:
        logging.info("Server shutting down...")

        for thread in active_threads:
            thread.join() # Wait for all threads to finish
        server_socket.close()
        logging.info("Server shutdown gracefully")
            

if __name__ == "__main__":
    logging.basicConfig(filename="ServerFiles/admin/server.log", level=logging.INFO, format="%(asctime)s - %(message)s")
    main()

    # Run the server and client scripts in separate terminal windows.
    # The server script should be run first.
