#!/usr/bin/python3
from socket import AF_INET, socket, SOCK_STREAM
import shared_curve
from ecc.Point import Point
from threading import Thread
from pprint import pprint
from block_cipher.cipher import BerezCipher
import sys

clients = {}
addresses = {}
keys = {}
shared_key= {}

pri, pub = shared_curve.curve.gen_key_pair()

HOST = ''
if (len(sys.argv) == 2):
    PORT = int(sys.argv[1])
else:
    PORT = 33000
BUFSIZ = 1024
ADDR = (HOST, PORT)
SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)
MODE = "CBC"

# MSG is string
def send_encrypted(client_socket, msg, key):
    cipher = BerezCipher(message=msg.encode('utf-8'), key = key, fromFile=False)
    ciphertext = cipher.generate_cipher(decrypt = False, mode = MODE)
    print("send_encrypted", key, ciphertext)
    client_socket.send(ciphertext)

def recv_encrypted(client_socket, key):
    msg = client_socket.recv(BUFSIZ)
    print("recv_encrypted", key, msg)

    cipher = BerezCipher(message=msg, key = key, fromFile=False)
    plaintext = cipher.generate_cipher(decrypt = True, mode = MODE)
    return plaintext.decode('utf-8').rstrip(' \t\r\n\0')


def secret_share(client):
    """Secret sharing"""
    global shared_key
    msg = str(pub.X) + '|' + str(pub.Y)
    client.send(bytes(msg, "utf8"))

    try:
        msg = client.recv(BUFSIZ).decode("utf8").split('|')
    except OSError:  # Possibly client has left the chat.
        pass

    partial_key = Point(int(msg[0]),int(msg[1]))
    shared_key[client] = shared_curve.curve.gen_shared_key(pri,partial_key)

    print("Shared Key :",shared_key[client].X, shared_key[client].Y)

def accept_incoming_connections():
    """Sets up handling for incoming clients."""
    while True:
        client, client_address = SERVER.accept()
        print("%s:%s has connected." % client_address)
        secret_share(client)
        client.send(bytes("Greetings from the cave! "+
                          "Now type your name and press enter!\n", "utf8"))
        # HANDSHAKE disini
        keys[client] = "123"
        addresses[client] = client_address
        send_encrypted(client, "Greetings from the cave! \n Now type your name and press enter!\n",
                        keys[client])

        Thread(target=handle_client, args=(client,)).start()


def handle_client(client):  # Takes client socket as argument.
    """Handles a single client connection."""
    name = recv_encrypted(client, keys[client])
    clients[client] = name
    welcome = 'Welcome %s! If you ever want to quit, type {quit} to exit.\n' % name
    send_encrypted(client, welcome, keys[client])

    msg = "%s has joined the chat!" % name
    broadcast(msg)

    while True:
        msg = recv_encrypted(client, keys[client])
        if msg != "{quit}":
            broadcast(msg, name+": ")
        else:
            client.close()
            del clients[client]
            msg = "%s has left the chat." % name
            broadcast(msg)
            break


def broadcast(msg, prefix=""):  # prefix is for name identification.
    """Broadcasts a message to all the clients."""
    for sock in clients:
        # encrypt
        send_encrypted(sock, prefix + msg, keys[sock])


if __name__ == "__main__":
    SERVER.listen(5)  # Listens for 5 connections at max.
    print("Waiting for connection...")
    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
    ACCEPT_THREAD.start()  # Starts the infinite loop.
    ACCEPT_THREAD.join()
    SERVER.close()
