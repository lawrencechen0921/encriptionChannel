import socket
import threading

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432 


from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


with open("public_keyClient.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

with open("private_keyServer.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        backend=default_backend(),
        password=None
    )


message = b'encrypt me!'

encrypted = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

def encryptMessage(message,key):
    encrypted = key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted
    
def decryptMessage(encrypted,key):
    original_message = key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return original_message

def receiveListeningChannel(s):
    s.recv(1024)
    s.sendall(b'Ok')
    receivingHost = s.recv(1024)
    s.sendall(b'Ok')
    receivingPort = s.recv(1024)
    s.sendall(b'Ok')
    print(receivingHost, receivingPort)
    return receivingHost, receivingPort

def connectToListeningPort(host, port):
    s.connect((host, int(port)))
    return s

# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#     s.bind((HOST, PORT))
#     s.listen()
#     conn, addr = s.accept()
#     with conn:
#         print('Connected by', addr)
#         while True:
#             data = conn.recv(1024)
#             if not data:
#                 break
#             conn.sendall(encrypted)

def setReceiver(host,port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host,port))
        s.listen()
        conn, addr = s.accept()
        with conn:
            recHost, recPort = receiveListeningChannel(conn)
            sendingThread = threading.Thread(target=setSender, args=(recHost,recPort))
            sendingThread.start()
            handleReceiving(conn)
    

def setSender(host,port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host,int(port)))
        handleSending(s)

def handleSending(socket):
    global public_key
    while True:
        message = input("Message: ")
        socket.sendall(encryptMessage(bytes(str(message),'utf-8'),public_key))
        data = socket.recv(1024)
        if not data:
            break

def handleReceiving(s):
    global private_key
    while True:
        print("Reading")
        data = s.recv(1024)
        if not data:
            break
        print("El cliente dice raw", data)
        data = decryptMessage(data,private_key)
        if (str(data)=="adios"):
            print("El cliente dice adios")
            break
        print("El cliente dice", data)
        s.sendall(b'Ok')

def main():
    setReceiver(HOST,PORT)

    # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    #     s.bind((HOST, PORT))
    #     s.listen()
    #     conn, addr = s.accept()
    #     with conn:
    #         print('Connected by', addr)
    #         recHost, recPort = receiveListeningChannel(conn)
    #         s_out = connectToListeningPort(s, recHost, recPort)
    #         receiveingThread = threading.Thread(target=handleReceiving, args=(conn,))
    #         sendingThread = threading.Thread(target=handleSending, args=(s_out,))
    #         receiveingThread.start()
    #         sendingThread.start()


main()
