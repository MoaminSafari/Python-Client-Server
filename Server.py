import socket
import threading
from cryptography.fernet import Fernet

username_password = {}
fernet = Fernet(Fernet.generate_key())
username_socket = {}
username_messages = {}
groups = {}
status = {}


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

def update_client(username, password, client_socket):
    username_password.update(
                    {username: fernet.encrypt(password.encode('utf-8'))})
    username_socket.update({username: client_socket})
    status.update({username: 'Available'})

def create_group(username, group_name):
    if group_name not in groups:
        groups[group_name] = [username_socket[username]]
        return f'Group {group_name} created successfully'
    else:
        return f'Group {group_name} already exists'


def join_group(username, group_name):
    if group_name in groups:
        groups[group_name].append(username_socket[username])
        return f'{username} joined group {group_name}'
    else:
        return f'Group {group_name} not found'


def group_message(username, group_name, message):
    if group_name in groups:
        if username_socket[username] in groups[group_name]:
            for member_socket in groups[group_name]:
                member_socket.send(
                    f'Group message from {username} in {group_name}:\n{message}'.encode('utf-8'))
            return f'Group message sent to {group_name}'
        else:
            return f'you are not allowed to send message in this Group {group_name} '
    else:
        return f'Group {group_name} not found'


def group_actions(username, message, dest_name):
    command, group_name = dest_name.split(':')
    if command == '@create':
        return create_group(username, group_name)
    if command == '@join':
        return join_group(username, group_name)
    if command == '@group':
        response = group_message(
            username, group_name, message)
        if response == f'Group message sent to {group_name}':
            username_messages[username].append(
                f'From: {username}\nTo group: {group_name}\n{message}')
        return response
    return 'Invalid group command'


def public_message(username, message):
    username_messages[username].append(
        f'From: {username}\nTo: Public\n{message}')
    for client in username_socket.values():
        clientstatus = status[list(username_socket.keys())[list(
            username_socket.values()).index(client)]]
        if clientstatus != 'Busy':
            client.send(
                f'Public message from {username}:\n{message}'.encode('utf-8'))


def private_message(username, message, dest_name):
    clientstatus = status[dest_name]
    if clientstatus != 'Busy':
        username_messages[username].append(
            f'From: {username}\nTo: {dest_name}\n{message}')
        username_socket[dest_name].send(
            f'Private message from {username}:\n{message}'.encode('utf-8'))
        return True
    else:
        return False


def show_previous_messages(username, client_socket):
    if username in username_messages and len(username_messages[username]) != 0:
        client_socket.send(f'Older messages:\n'.encode('utf-8'))
        for message in username_messages[username]:
            client_socket.send(f'{message}\n'.encode('utf-8'))
    else:
        client_socket.send(f'There are no messages\n'.encode('utf-8'))
        username_messages[username] = []


def init_client(client_socket):
    username = ''
    while True:
        data = client_socket.recv(1024)
        log_or_sign, username, password = data.decode(
            'utf-8').split('\n\0\n', 2)
        print(
            f'{log_or_sign} for {client_socket.getpeername()[0]}:{client_socket.getpeername()[1]}')
        print(
            f'Received Username for {client_socket.getpeername()[0]}:{client_socket.getpeername()[1]}: {username}')

        response = username_check(username, log_or_sign)
        if response == 'Client Initialized':
            response = password_check(username, password, log_or_sign)
            if response == 'Authenticated':
                update_client(username, password, client_socket)
        client_socket.send(response.encode('utf-8'))
        if response == 'Authenticated':
            show_previous_messages(username, client_socket)
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
        username = list(username_socket.keys())[
            list(username_socket.values()).index(client_socket)]
        if dest_name == '@status':
            new_status = message.strip()
            status[username] = new_status
            response = f'Status Changed'
        elif dest_name.startswith('@'):
            response = group_actions(username, message, dest_name)
        elif dest_name == 'public':
            public_message(username, message)
        elif dest_name in username_socket.keys():
            if not private_message(username, message, dest_name):
                response = f'{dest_name} this user is in Busy status'
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
        udp_socket.sendto(
            str(list(username_password.keys())).encode('utf-8'), addr)


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
            client_handler = threading.Thread(
                target=handle_client, args=(client,))
            client_handler.start()
    except Exception as e:
        print(f"Error: {str(e)}")


if __name__ == '__main__':
    main()
