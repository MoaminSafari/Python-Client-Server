import socket
import threading

def see_all_clients():
    try:
        server_address = ('127.0.0.1', 11521)
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.sendto('see clients'.encode('utf-8'), server_address)
        response, addr = udp_socket.recvfrom(1024)
        print(f"Connected clients: {response.decode('utf-8')}")
        udp_socket.close()
    except Exception as e:
        print(f"Error seeing clients: {str(e)}")


def send_messages(client, action):
    receiver = 'public'
    if action == '1':
        receiver = input('Enter receiver username or group name (start with @): ')
    message = input('Enter message: ')
    client.send(f'{receiver}\n\0\n{message}'.encode('utf-8'))
    print(client.recv(1024).decode('utf-8'))

def receive_messages(client_socket):
    while True:
        try:
            response = client_socket.recv(1024)
            if not response:
                break
            print(f"{response.decode('utf-8')}")
        except Exception as e:
            print(f"Error receiving message: {str(e)}")
            break

def init_client(client, log_or_sign):
    while True:
        username = input("Enter Username (type 'exit' to quit): ")
        if username.lower() == 'exit':
            return False
        password = input("Enter Password: ")
        client.send(f'{log_or_sign}\n\0\n{username}\n\0\n{password}'.encode('utf-8'))
        response = client.recv(1024)
        if response.decode('utf-8') == 'Authenticated':
            return True
        print(response.decode('utf-8'))


def connect_to_server(server_address, log_or_sign):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(server_address)
        print("Connected to server")
        if not init_client(client, log_or_sign):
            client.close()
            return
        receive_thread = threading.Thread(target=receive_messages, args=(client,))
        receive_thread.start()
        while True:
            action = input('1. Send private message\n2. Send public message\n3. See all clients\n4. Group actions\n5. Exit\nEnter Num:\n')
            if action == '1' or action == '2':
                send_messages(client, action)
            elif action == '3':
                see_all_clients()
            elif action == '4':
                create_or_join_group(client)
            elif action == '5':
                break
            else:
                print('Invalid action')
    except Exception as e:
        print(f"Error while connecting to server: {str(e)}")

def create_or_join_group(client):
    group_action = input('1. Create a group\n2. Join a group\nEnter Num:\n')
    if group_action == '1':
        group_name = input('Enter group name: ')
        client.send(f'@create:{group_name}\n\0\n'.encode('utf-8'))
        print(client.recv(1024).decode('utf-8'))
    elif group_action == '2':
        group_name = input('Enter group name to join: ')
        client.send(f'@join:{group_name}\n\0\n'.encode('utf-8'))
        print(client.recv(1024).decode('utf-8'))
    else:
        print('Invalid group action')

def main():
    while True:
        f_action = input('1. Log in\n2. Sign up\n3. See all clients\n4. Exit\nEnter Num:\n')
        if f_action == '1':
            connect_to_server(('127.0.0.1', 11520), 'login')
        elif f_action == '2':
            connect_to_server(('127.0.0.1', 11520), 'signup')
        elif f_action == '3':
            see_all_clients()
        elif f_action == '4':
            break
        else:
            print('Invalid action')

if __name__ == "__main__":
    main()
