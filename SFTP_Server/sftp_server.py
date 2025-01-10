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



# Function to start the SFTP server
def start_sftp_server():
    # Load host keys
    host_key = paramiko.RSAKey(filename="ServerFiles/admin/SFTPserver.key")

    # Create a transport object
    transport = Transport((HOST, PORT))
    transport.add_server_key(host_key)


    # Define the custom auth server
    server = paramiko.ServerInterface()

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