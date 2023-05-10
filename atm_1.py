import socket
import ssl

#from bank import SERVER as SERVER_HOST
#from bank import PORT as SERVER_PORT

HEADER = 64
PORT = 5054
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
client.connect(ADDR)

def send(msg):
    message = msg.encode(FORMAT)
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(message)
    print(client.recv(2048).decode(FORMAT))


print("[Hello! This is ATM 1]")
print("Please enter you ID")
id = input()
print("Please enter your password")
passowrd = input()

# send("Hello World!")
# input()
# send("Hello Everyone!")
# input()
# send("Hello Tim!")

# send(DISCONNECT_MESSAGE)