#!/usr/bin/env python3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import threading
import socket

receiving_host = '127.0.0.1'  # The server's hostname or IP address
receiving_port = 10000        # The port used by the server

with open("private_keyClient.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        backend=default_backend(),
        password=None
    )


with open("public_keyServer.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )




def getPublicKey():
	with open("private_keyClient.pem", "rb") as key_file:
	    private_key = serialization.load_pem_private_key(
	        key_file.read(),
	        backend=default_backend(),
	        password=None
	    )
	    return private_key

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

def sendListeningChannel(socket):
	socket.sendall(b'Listening on')
	socket.recv(1024)
	socket.sendall(bytes(receiving_host,'utf-8'))
	socket.recv(1024)
	socket.sendall(bytes(str(receiving_port),'utf-8'))
	socket.recv(1024)

def getListenerSocket(s, host, port):
    s.bind((host, port))
    s.listen()
    conn, addr = s.accept()
    return conn, addr

def handleSending(socket):
	global public_key
	while True:
 		message = input("Message: ")
 		socket.sendall(encryptMessage(bytes(str(message),'utf-8'),public_key))
 		data = socket.recv(1024)
 		if not data:
 			break

def handleReceiving(socket):
	global private_key
	while True:
		data = socket.recv(1024)
		if not data:
			break
		print("El servidor dice raw", data)
		data = decryptMessage(data,private_key)
		if (str(data)=="adios"):
			print("El servidor dice adios")
			break
		print("El servidor dice", data)
		socket.sendall(b'Ok')

# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#     s.connect((HOST, PORT))
#     s.sendall(b'Hello, world')
#     data1 = s.recv(1024)
#     data2 = decryptMessage(data1,private_key)

# print('Received', repr(data2), repr(data1))

def setSender(host,port):
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.connect((host,port))
		sendListeningChannel(s)
		handleSending(s)

def setReceiver(host, port):
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		conn, addr = getListenerSocket(s,host,port)
		handleReceiving(conn)

def main():
	print("Bienvenido al canal encriptado")
	host = input("Indique la direccion con la que quiere conectarse: ")
	port = input("Indique el puerto con el que quiere conectarse: ")
	sendingThread = threading.Thread(target=setSender, args=(host,int(port)))
	receiveingThread = threading.Thread(target=setReceiver, args=(receiving_host,receiving_port))
	receiveingThread.start()
	sendingThread.start()


main()
