import socket
from tkinter.filedialog import askopenfilename
from tkinter import SEPARATOR

suckit = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
host = socket.gethostname()
port = 12345
SEPARATOR = "<SEPARATOR>"


def login():
    print("Usuario:")
    user = input()
    print("Contraseña:")
    password = input()
    userdata=[user, password]
    return userdata
    

if __name__ == "__main__":
    user = login()
    file = askopenfilename()
   
    data = open(file,'rb').read()
    suckit.connect((host, port))
    print ('Mandando...')
    suckit.sendall(f"{data}{SEPARATOR}{user[0]}{SEPARATOR}{user[1]}".encode())
    data = suckit.recv(4096)
    print(data.decode())
    suckit.close               


