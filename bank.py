import socket
import threading
import sys
import os

HEADER = 2048
PORT = 5051
SERVER = socket.gethostbyname(socket.gethostbyname("localhost"))
ADDR = (SERVER, PORT)
FORMAT = "utf-8"
DC = "GOODBYE"
COMMAND = []

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)


def start():
    server.listen()
    print(f"Server is [LISTENING] on {SERVER}\n")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[Connections currently Active] {threading.active_count() - 1}\n")


# This code allows us to print the current working directory
def list_files_in_current_directory():
    conn, addr = server.accept()
    current_directory = os.getcwd()
    files_and_directories = os.listdir(current_directory)

    for item in files_and_directories:
        conn.send(f"{item}".encode(FORMAT))


# This code enables us to use the "Get" command in our current working dirrectory:

def get_file_content(file_name):
    current_directory = os.getcwd()
    file_path = os.path.join(current_directory, file_name)

    if os.path.isfile(file_path):
        with open(file_path, 'r') as file:
            content = file.read()
        return content
    else:
        print(f"'{file_name}' does not exist in the current directory.")
        return None


def handle_client(conn, addr):
    print(f"[New connection Incoming] {addr} has connected.\n")

    # keeping the connection alive with a while loop untill client enters quit
    connected = True
    while connected:
        msg_length = conn.recv(HEADER).decode(FORMAT)
        # checks for msg after the initial blank message that initiates the connection
        if msg_length:
            msg_length = int(msg_length)
            msg = conn.recv(msg_length).decode(FORMAT)
            if msg == DC:
                connected = False
            print(f"[{SERVER}] has sent '{msg}'!")

            # if users enters ls command we print out whats in our CWD
            if msg == "ls":
                list_files_in_current_directory()
            elif msg != "ls":
                COMMAND = msg.split()
                if COMMAND[0] == "get":
                    get_file_content(COMMAND[1])

    conn.close()


print("[STARTING] server starting.....")

start()
