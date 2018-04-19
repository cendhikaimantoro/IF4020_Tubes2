#!/usr/bin/python3
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from block_cipher.cipher import BerezCipher
from ecc.Point import Point
import tkinter
import shared_curve
import sys

client_socket = socket(AF_INET, SOCK_STREAM)
KEY = ""
MODE = "CBC"

def send_encrypted(msg):
    cipher = BerezCipher(message=msg.encode('utf-8'), key = KEY, fromFile=False)
    ciphertext = cipher.generate_cipher(decrypt = False, mode = MODE)
    print("send_encrypted", KEY, ciphertext)
    client_socket.send(ciphertext)

def recv_encrypted():
    msg = client_socket.recv(BUFSIZ)
    print("recv_encrypted", KEY, msg)
    cipher = BerezCipher(message=msg, key = KEY, fromFile=False)
    plaintext = cipher.generate_cipher(decrypt = True, mode = MODE)
    return plaintext.decode('utf-8').rstrip(' \t\r\n\0')

def receive():
    """Handles receiving of messages."""
    while True:
        try:
            msg = recv_encrypted()
            # decrypt
            msg_list.insert(tkinter.END, msg)
        except OSError:  # Possibly client has left the chat.
            break

def send(event=None):  # event is passed by binders.
    """Handles sending of messages."""
    msg = my_msg.get()
    my_msg.set("")  # Clears input field.

    send_encrypted(msg)

    if msg == "{quit}":
        client_socket.close()
        top.quit()

def secret_share():
    """Secret sharing"""
    global shared_key
    msg = str(pub.X) + '|' + str(pub.Y)
    client_socket.send(bytes(msg, "utf8"))

    try:
        msg = client_socket.recv(BUFSIZ).decode("utf8").split('|')
    except OSError:  # Possibly client has left the chat.
        pass

    partial_key = Point(int(msg[0]),int(msg[1]))
    shared_key = shared_curve.curve.gen_shared_key(pri,partial_key)
    print("Shared Key :", shared_key.X, shared_key.Y)

def on_closing(event=None):
    """This function is to be called when the window is closed."""
    my_msg.set("{quit}")
    send()

top = tkinter.Tk()
top.title("Chatter")

messages_frame = tkinter.Frame(top)
my_msg = tkinter.StringVar()  # For the messages to be sent.
my_msg.set("Type your messages here.")
scrollbar = tkinter.Scrollbar(messages_frame)  # To navigate through past messages.

# Following will contain the messages.
msg_list = tkinter.Listbox(messages_frame, height=15, width=70, yscrollcommand=scrollbar.set)
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
msg_list.pack()
messages_frame.pack()

entry_field = tkinter.Entry(top, textvariable=my_msg, width=30)
entry_field.bind("<Return>", send)
entry_field.pack()
send_button = tkinter.Button(top, text="Send", command=send)
send_button.pack()

top.protocol("WM_DELETE_WINDOW", on_closing)

#----Now comes the sockets part----
HOST = sys.argv[1]
PORT = int(sys.argv[2])

BUFSIZ = 1024
ADDR = (HOST, PORT)

client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDR)

#----Key Sharing----
pri, pub = shared_curve.curve.gen_key_pair()
shared_key = Point(0,0)
secret_share()

KEY = "123"
receive_thread = Thread(target=receive)
receive_thread.start()
tkinter.mainloop() # Starts GUI execution.
