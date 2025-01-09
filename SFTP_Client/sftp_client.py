import paramiko
import os
import sys
from paramiko import ssh_exception

# Define the server address and port
HOST = '172.212.203.54'  # Replace with your VM's public IP address
PORT = 22

def connect_to_server():
    # Prompt for username and password
    username = input("Enter your SSH username: ").strip()
    password = input("Enter your SSH password: ").strip()

    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to the server
    print(f"Connecting to {HOST} on port {PORT}")
    try:
        ssh_client.connect(HOST, port=PORT, username=username, password=password)
    except ssh_exception.AuthenticationException:
        print("Authentication failed. Please check your credentials.")
        sys.exit(1)
    except ssh_exception.NoValidConnectionsError:
        print("Unable to connect to the server.")
        sys.exit(1)
    except Exception as e:
        print("An error occurred:", e)
        sys.exit(1)

    # Create an SFTP session
    sftp_client = ssh_client.open_sftp()
    return ssh_client, sftp_client

def upload_file(sftp_client):
    # Example of local_file_path
    print("Example of local_file_path:")
    print("Windows: C:\\Users\\YourUsername\\Documents\\example.txt")
    print("Linux/macOS: /home/yourusername/Documents/example.txt")
    
    local_file_path = input("Enter the path to the local file to upload: ").strip()
    remote_file_path = input("Enter the path on the server to upload the file to: ").strip()
    if os.path.exists(local_file_path):
        sftp_client.put(local_file_path, remote_file_path)
        print(f"File {local_file_path} uploaded to {remote_file_path}")
    else:
        print(f"Local file {local_file_path} does not exist.")

def download_file(sftp_client):
    remote_file_path = input("Enter the path to the remote file to download: ").strip()
    local_file_path = input("Enter the path on the local machine to save the file: ").strip()
    sftp_client.get(remote_file_path, local_file_path)
    print(f"File {remote_file_path} downloaded to {local_file_path}")

def main():
    ssh_client, sftp_client = connect_to_server()

    while True:
        print("\nOptions:")
        print("1. Upload a file")
        print("2. Download a file")
        print("3. Exit")
        choice = input("Enter your choice: ").strip()

        if choice == '1':
            upload_file(sftp_client)
        elif choice == '2':
            download_file(sftp_client)
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

    # Close the SFTP session and SSH client
    sftp_client.close()
    ssh_client.close()

if __name__ == "__main__":
    main()