import socket
import json
import nacl.utils
from Crypto.Cipher import ChaCha20
import nacl.secret
import datetime
from tkinter import SEPARATOR
from nacl.signing import SigningKey
from nacl.signing import VerifyKey
from base64 import b64decode, b64encode


suckit = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = socket.gethostname()
port = 12345
suckit.bind((host, port))
SEPARATOR = "<SEPARATOR>"

def Cipher(data):
    key=nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    cipher= ChaCha20.new(key=key)
    encrypted=cipher.encrypt(data.encode())
    nonce=b64encode(cipher.nonce).decode()
    encrypted_txt = b64encode(encrypted).decode()
    json_cifrado = json.dumps({'nonce': nonce, "texto_cifrado": encrypted_txt})

    f = open('archvio_encriptado.txt','w') 
    f.write(str(encrypted))
    f.close

    final=[encrypted, json_cifrado, key]

    return final

def Decipher(data:str, key):
    jsondata = json.loads(data)
    nonce = b64decode(jsondata['nonce'])
    texto_cifrado = b64decode(jsondata['texto_cifrado'])
    cipher = ChaCha20.new(key=key, nonce=nonce)
    texto_descifrado = cipher.decrypt(texto_cifrado)
        
    f = open("archivo_descifrado.txt", "w")
    f.write(str(texto_descifrado))
    f.close()

    return texto_descifrado.decode('utf-8')

def Sign(data):
    key = SigningKey.generate()
    firma = key.sign(data)

    f = open("archvio_encriptado.txt", "a")
    f.write(f'\n{firma}')
    f.close()

    final=[firma, key]
    return final

def VerifySign(data, key):
    vkey = VerifyKey(key.verify_key.encode())
    vfirma = vkey.verify(data)
    f = open("archivo_descifrado.txt", "a")
    f.write(f'\n{vfirma}')
    f.close()
    return vfirma 

def Login(user, password):
    time = datetime.datetime.now()
    file = open("bitacora.txt", "a")
    if user=="Alonso" and password=="owo":
        file.write(f"{time}   Entro Alonso\n")
        return True
    file.write(f"{time}   Intento entrar: {user}\n")
    file.close()
    return False


if __name__ == "__main__":
    suckit.listen()
    print ('Esperando conexión...')
    
    conn, addr = suckit.accept()
    print ('Conectado a', addr )
    print ('Recibiendo')
    message = conn.recv(4096).decode()
    file, user, password = message.split(SEPARATOR)

    if not Login(user, password):
        conn.sendall(f"Usario o contrasña no valida: {user}".encode())
    else:
        results_Cipher=Cipher(file)
        desciphered=Decipher(results_Cipher[1], results_Cipher[2])
        results_Sign = Sign(results_Cipher[0])
        verified = VerifySign(results_Sign[0], results_Sign[1])
        conn.sendall('El archivo a sido, cifrado, descifrado, firmado y verificado\n'.encode())
    suckit.close()      


    