import os
import paramiko
from paramiko import Transport, SFTPServer, SFTPServerInterface, SFTPAttributes, SFTPHandle
import logging
import hashlib


HOST = '0.0.0.0'
PORT = 22
BASE_DIR = "ServerFiles"
PWD_FILE = "ServerFiles/admin/lsu.txt"


# Logging
logging.basicConfig(filename="ServerFiles/admin/sftp_server.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Define the SFTP server interface
class MySFTPServer(SFTPServerInterface):
    def __init__(self, server, *largs, **kwargs):
        super(MySFTPServer, self).__init__(server, *largs, **kwargs)

    def list_folder(self, path):
        logging.info("Listing folder: %s", path)
        real_path = os.path.join(BASE_DIR, path.lstrip('/'))
        try:
            files = os.listdir(real_path)
            return [SFTPAttributes.from_stat(os.stat(os.path.join(real_path, f))) for f in files]
        except FileNotFoundError:
            return []

    def open(self, path, flags, attr):
        logging.info("Opening file: %s", path)
        real_path = os.path.join(BASE_DIR, path.lstrip('/'))
        try:
            handle = SFTPHandle(real_path)
            handle.filename = real_path
            handle.flags = flags
            handle.attr = attr
            return handle
        except FileNotFoundError:
            return SFTPHandle()

    def remove(self, path):
        logging.info("Removing file: %s", path)
        real_path = os.path.join(BASE_DIR, path.lstrip('/'))
        try:
            os.remove(real_path)
            return SFTP_OK
        except FileNotFoundError:
            return SFTP_NO_SUCH_FILE

    def rename(self, oldpath, newpath):
        logging.info("Renaming file from %s to %s", oldpath, newpath)
        real_oldpath = os.path.join(BASE_DIR, oldpath.lstrip('/'))
        real_newpath = os.path.join(BASE_DIR, newpath.lstrip('/'))
        try:
            os.rename(real_oldpath, real_newpath)
            return SFTP_OK
        except FileNotFoundError:
            return SFTP_NO_SUCH_FILE

# Define the Custom Auth Server Interface
class CustomAuthServer(paramiko.ServerInterface):
    """
    Custome Paramko server interface for authentication
    """

    def __init__(self, creds):
        super().__init__()
        self.creds = creds

    def check_auth_password(self, username, password):
        """
        Check the user provided pass with stored hash
        """
        if username in self.creds:
            stored_hash = self.creds[username]['hash']
            privided_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
            if stored_hash == privided_hash:
                return paramiko.AUTH_SUCCESSFUL
            
        return paramiko.AUTH_FAILED
    
    # def check_user_role(self, username):

# Authentication
def load_credentials(lsu_file):
    """
    Returns a dictionary with the credentials:
    {
        "username": "hashedPassword": "role"
    }
    """

    creds = {}
    if os.path.exists(lsu_file):
        with open(lsu_file, "r", encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("//"):
                    continue

                # Fromat: username:hashedPassword:role
                parts = line.split(":")
                if len(parts) == 3:
                    username, hashPass, role = parts
                    creds[username] = {
                        "hashedPassword": hashPass,
                        "role": role
                    }

    return creds




# Function to start the SFTP server
def start_sftp_server():
    # Load host keys
    host_key = paramiko.RSAKey(filename="ServerFiles/admin/SFTPserver.key")

    # Create a transport object
    transport = Transport((HOST, PORT))
    transport.add_server_key(host_key)

    # Load credentials from lsu.txt
    creds = load_credentials(PWD_FILE)

    # Define the custom auth server
    server = CustomAuthServer(creds)

    # Start the transport
    transport.start_server(server=server)

    # Accept an SFTP connection
    channel = transport.accept()
    if channel is None:
        logging.error("Failed to accept channel")
        return

    # Start the SFTP server
    sftp_server = SFTPServer(channel, MySFTPServer)
    sftp_server.serve_forever()

# Main function to start the server
if __name__ == "__main__":
    logging.info("Starting SFTP server on %s:%s", HOST, PORT)
    start_sftp_server()