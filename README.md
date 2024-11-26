
# Secure File Transfer Application

## Overview

This project implements a secure client-server file transfer system using **SSL/TLS** for encrypted communication. It integrates authentication, role-based access control (RBAC), and logging mechanisms to ensure data confidentiality, integrity, and secure file management.

----------

## Features

1.  **Encrypted Communication**:
    
    -   All communication between the client and server is secured with **SSL/TLS**.
        
2.  **Authentication**:
    
    -   Users authenticate using a **username** and **password**.
        
    -   Passwords are stored securely as **SHA-256 hashes**.
        
3.  **Role-Based Access Control (RBAC)**:
    
    -   Roles:
        
        -   **Admin**: Full permissions (upload, download, list, delete, manage).
            
        -   **User**: Limited permissions (upload, download, list).
            
    -   Permissions are enforced server-side.
        
4.  **File Operations**:
    
    -   **Upload**: Send files to the server.
        
    -   **Download**: Retrieve files from the server.
        
    -   **List**: View files in the user's directory.
        
    -   **Delete**: Admin-only feature to remove files.
        
5.  **Logging**:
    
    -   All actions are logged for auditing, including authentication attempts and file operations.
        

----------

## System Architecture

### Client

-   The client sends commands to the server and receives responses.
    
-   Commands include: `upload`, `download`, `list`, `delete`, and `manage`.
    
-   It verifies the server's identity using the **server.crt** file.
    

### Server

-   The server authenticates clients and enforces RBAC.
    
-   Stores files in user-specific directories.
    
-   Loads credentials from a file (`pwd.txt`).
    
-   Uses the following files:
    
    -   `server.crt`: Server's public certificate.
        
    -   `server.key`: Server's private key.
        
----------

## Running the Project


### Start the Server

Run the server script:

```
python tcp_server.py
```

-   The server listens on `127.0.0.1:10615` by default.
    
-   Logs are stored in `ServerFiles/admin/server.log`.
    

### Start the Client

Run the client script:

```
python tcp_client.py
```

-   The client connects to the server and provides a command-line interface for interacting with the server.
    

----------

## File Commands

### Authentication

The client must log in with a valid username and password stored in `pwd.txt`. Users and their login credentials must be inputted manually into the text file, for now.

### Supported Commands

1.  **Upload**:
    
    ```
    upload <filename>
    ```
    
    -   Sends a file to the server.
        
2.  **Download**:
    
    ```
    download <filename>
    ```
    
    -   Retrieves a file from the server.
        
3.  **List**:
    
    ```
    list
    ```
    
    -   Displays the files available in the user's directory.
        
4.  **Delete** (Admin-only):
    
    ```
    delete <filename>
    ```
    
    -   Removes a file from the server.
    
5.  **Manage** (Admin-only):
    
    ```
    manage
    ```
    
    -   Prints a message to the client about proposed management feature.
        
5.  **Exit**:
    
    ```
    exit
    ```
    
    -   Closes the connection.
        

----------

## Security Considerations

1.  **SSL/TLS**:
    
    -   All communication is encrypted, ensuring confidentiality and integrity.
        
2.  **Private Key Security**:
    
    -   The `server.key` file is critical and should be kept secure with restricted permissions (e.g., `chmod 600`).
        
3.  **Password Hashing**:
    
    -   Passwords are hashed with SHA-256 before being stored in `pwd.txt`.
        
4.  **Role Enforcement**:
    
    -   Role-based permissions prevent unauthorized actions.
        

----------

## Future Enhancements

-   **File Access Restrictions**: Clients should be confined to their directories. Attempts to access files outside their directory, such as admin files, should be blocked server-side

-   **Database Integration**: Replace `pwd.txt` with a database for scalability and security.
    
-   **Shared Directory**: Introduce a shared folder accessible by all users.
    
-   **Guest Role**: Add a more meaningful `guest` role and user with limited permissions (e.g., list-only access).
    
-   **Enhanced Logging**: Include more detailed audit logs. Timestamps, IP.
    
-   **File Management**: Expand the `manage` command for advanced file and user administration.
    

----------

