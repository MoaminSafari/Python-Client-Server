import socket
import threading
from cryptography.fernet import Fernet

username_password = {}
username_socket = {}
key = Fernet.generate_key()
fernet = Fernet(key)
groups = {}

def create_group(username, group_name):
    if group_name not in groups:
        groups[group_name] = [username_socket[username]]
        return f'Group {group_name} created successfully'
    else:
        return f'Group {group_name} already exists'



def password_check(username, password, log_or_sign):
    print(f'Received Password for {username}: {password}')
    if log_or_sign == 'login':
        if password == fernet.decrypt(username_password[username]).decode('utf-8'):
            return 'Authenticated'
        else:
            return 'Wrong Password,\nPlease try again:\n'
    elif log_or_sign == 'signup':
        return 'Authenticated'

def username_check(username, log_or_sign):
    if log_or_sign == 'login':
        if username not in username_password.keys():
            return 'Username not found,\nPlease try again:\n'
        else:
            return 'Client Initialized'
    elif log_or_sign == 'signup':
        if username == 'public':
            return 'You cannot use this username\nPlease try again:\n'
        elif username in username_password.keys():
            return 'Username already taken,\nPlease try again:\n'
        else:
            return 'Client Initialized'

def init_client(client_socket):
    username = ''
    while True:
        data = client_socket.recv(1024)
        log_or_sign, username, password = data.decode('utf-8').split('\n\0\n', 2)
        print(f'{log_or_sign} for {client_socket.getpeername()[0]}:{client_socket.getpeername()[1]}')
        print(f'Received Username for {client_socket.getpeername()[0]}:{client_socket.getpeername()[1]}: {username}')

        response = username_check(username, log_or_sign)
        if response == 'Client Initialized':
            response = password_check(username, password, log_or_sign)
            if response == 'Authenticated':
                username_password.update({username: fernet.encrypt(password.encode('utf-8'))})
                username_socket.update({username: client_socket})

        client_socket.send(response.encode('utf-8'))
        if response == 'Authenticated':
            break

    print(f'Client {username} Initialized')

def handle_client(client_socket):
    init_client(client_socket)
    while True:
        data = client_socket.recv(1024)
        if not data:
            break
        decoded_data = data.decode('utf-8')
        dest_name, message = decoded_data.split('\n\0\n', 1)
        response = f'Message sent to {dest_name}'
        if dest_name == 'public':
            for client in username_socket.values():
                client.send(f'Public message from {list(username_socket.keys())[list(username_socket.values()).index(client_socket)]}:\n{message}'.encode('utf-8'))
        elif dest_name in username_socket.keys():
            username_socket[dest_name].send(f'Private message from {list(username_socket.keys())[list(username_socket.values()).index(client_socket)]}:\n{message}'.encode('utf-8'))
        else:
            response = 'Invalid destination'
        client_socket.send(response.encode('utf-8'))
    client_socket.close()

def udp_see_clients():
    server_address = ('127.0.0.1', 11521)
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(server_address)
    while True:
        data, addr = udp_socket.recvfrom(1024)
        if not data:
            break
        udp_socket.sendto(str(list(username_password.keys())).encode('utf-8'), addr)

def main():
    try:
        udp_thread = threading.Thread(target=udp_see_clients)
        udp_thread.start()
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('127.0.0.1', 11520))
        server.listen(5)
        print('*Server listening messages on port 11520*')
        while True:
            client, addr = server.accept()
            print(f'*Accepted connection from {addr[0]}:{addr[1]}*')
            client_handler = threading.Thread(target=handle_client, args=(client,))
            client_handler.start()
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == '__main__':
    main()
