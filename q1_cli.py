import socket
import threading
from datetime import datetime

class Client:
    def __init__(self):
        self.isLoggedIn = False
        self.server = None
        self.lock = threading.Lock()
        self.status = None

    def see_all_clients(self):
        try:
            server_address = ('127.0.0.1', 11521)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
                udp_socket.sendto('see clients'.encode('utf-8'), server_address)
                response, addr = udp_socket.recvfrom(1024)
                print(f"Connected clients: {response.decode('utf-8')}")
        except Exception as e:
            print(f"Error seeing clients: {str(e)}")

    def send_messages(self, action):
        receiver = 'public'
        if action == '1':
            receiver = input('Enter receiver username or group name (start with @): ')
        message = input('Enter message: ')
        now = datetime.now()
        current_time = now.strftime("%H:%M")
        with self.lock:
            if receiver.startswith('@'):
                holder = receiver[1:]
                self.server.send(f'@group:{holder}\n\0\n{message}\n\t{current_time}'.encode('utf-8'))
            else:
                self.server.send(f'{receiver}\n\0\n{message}\n\t{current_time}'.encode('utf-8'))
                
    def receive_messages(self, client_socket):
        while True:
            try:
                response = client_socket.recv(1024)
                if response == None:
                    continue
                if response.decode('utf-8') == 'Authenticated':
                    with self.lock:
                        self.isLoggedIn = True
                elif response.decode('utf-8').startswith('@status:'):
                    with self.lock:
                        _,self.status = response.split(':')
                        response = f'status updated to {self.status}' 
                print(f"{response.decode('utf-8')}")
            except Exception as e:
                print(f"Error receiving message: {str(e)}")
                break

    def init_client(self, log_or_sign):
        if self.isLoggedIn or self.server is None:
            return
        username = input("Enter Username (type 'exit' to quit): ")
        if username=='exit':
            return False
        password = input("Enter Password: ")
        with self.lock:
            if self.server is not None:  # Check if the server socket is still valid
                print("checking the user name with server")
                self.server.send(f'{log_or_sign}\n\0\n{username}\n\0\n{password}'.encode('utf-8'))
        return True

    def connect_to_server_port(self, server_address):
        try:
            # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.connect(server_address)
            print("Connected to server")
            receive_thread = threading.Thread(target=self.receive_messages, args=(server,))
            receive_thread.daemon = True
            receive_thread.start()
            self.server = server
        except Exception as e:
            print(f"Error while connecting to server: {str(e)}")

    
    def changeStatus(self):
        message = input('set your status (busy, online, offline ,...): ')
        with self.lock:
            self.server.send(f'@status\n\0\n{message}'.encode('utf-8'))
 

    def connect_to_server(self):
        try:
            if self.server is None or not self.isLoggedIn:
                return

            while True:
                action = input(f'{self.status}\n0.Refresh\n1. Send private message\n2. Send public message\n3. See all clients\n4. Group actions\n5. status\n6. Exit\nEnter Num:\n')
                if action == '0':
                    continue
                elif action == '1' or action == '2':
                    self.send_messages(action)
                elif action == '3':
                    self.see_all_clients()
                elif action == '4':
                    self.create_or_join_group()
                elif action == '5':
                    self.changeStatus()
                elif action == '6':
                    break
                else:
                    print('Invalid action')

        except Exception as e:
            print(f"Error while connecting to server: {str(e)}")

    def create_or_join_group(self):
        group_action = input('1. Create a group\n2. Join a group\n3. Add memeber to a group\n4.exit \nEnter Num:\n')
        if group_action == '1':
            group_name = input('Enter group name: ')
            with self.lock:
                self.server.send(f'@create:{group_name}\n\0\n'.encode('utf-8'))
        elif group_action == '2':
            group_name = input('Enter group name to join: ')
            with self.lock:
                self.server.send(f'@join:{group_name}\n\0\n'.encode('utf-8'))
        elif group_action == '3':
            group_name = input('Enter group name to join: ')
            memeber_name = input('enter the member name: ')
            with self.lock:
                self.server.send(f'@add:{group_name}\n\0\n{memeber_name}'.encode('utf-8'))
        elif  group_action == '4':
            pass 
        else:
            print('Invalid group action')

def main():
    client = Client()
    client.connect_to_server_port(('127.0.0.1', 11520))

    while True:
        if client.isLoggedIn:
            client.connect_to_server()
            break
            
        f_action = input('0.Refresh\n1. Log in\n2. Sign up\n3. See all clients\n4. Exit\nEnter Num:\n')
        if f_action == '0':
            continue
        if f_action == '1':
            if client.init_client('login'):
                client.connect_to_server()
        elif f_action == '2':
            if client.init_client('signup'):
                client.connect_to_server()
        elif f_action == '3':
            client.see_all_clients()
        elif f_action == '4':
            break
        else:
            print('Invalid action')

if __name__ == "__main__":
    main()
