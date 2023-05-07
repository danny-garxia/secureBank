import socket
import sys
import os

HEADER = 2048
PORT = 5051
FORMAT = "utf-8"
DC = "GOODBYE"
SERVER = "localhost"

# SERVER = sys.argv[1] would be used if we would bind to 137.151.27.1 which is ecs.fullerton.edu IP
ADDR = (SERVER, PORT)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)


def send(msg):
    message = msg.encode(FORMAT)
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(message)
    

connected = True
while connected:

    command = input("ftp> ".split())

    if len(command) == 0:
        continue
    # allows user to exit with the following quit command
    if command == "quit":
        send(DC)
        print(f"[DISCONNECTING] from {sys.argv[1]}!!!!!!!")
        break
    # allows users to list the conntents of CWD
    elif command == "ls":
        send(command)
        print(client.recv(HEADER).decode(FORMAT))

    # Here we are sending over the command of get/pull which will be dealt with on the server side
    else:
        send(command)





