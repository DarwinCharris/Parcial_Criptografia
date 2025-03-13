import socket
import os
from Cryptodome.Cipher import ChaCha20, Salsa20

def cliente():
    cliente_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cliente_socket.connect(("128.0.0.1", 5555))
    
    algoritmo = input("Seleccione algoritmo (salsa20/chacha20): ").strip().lower()
    if algoritmo not in ['salsa20', 'chacha20']:
        print("Algoritmo no válido.")
        return
    
    cliente_socket.send(algoritmo.encode())
    clave = cliente_socket.recv(32)
    print("Clave recibida.")
    
    while True:
        mensaje = input("Cliente: ")
        nonce = os.urandom(8)
        cifrador = Salsa20.new(key=clave, nonce=nonce) if algoritmo == 'salsa20' else ChaCha20.new(key=clave, nonce=nonce)
        mensaje_cifrado = nonce + cifrador.encrypt(mensaje.encode())
        cliente_socket.send(mensaje_cifrado)
        
        respuesta_cifrada = cliente_socket.recv(1024)
        if not respuesta_cifrada:
            break
        
        nonce = respuesta_cifrada[:8] if algoritmo == 'salsa20' else respuesta_cifrada[:8]
        cifrador = Salsa20.new(key=clave, nonce=nonce) if algoritmo == 'salsa20' else ChaCha20.new(key=clave, nonce=nonce)
        respuesta_descifrada = cifrador.decrypt(respuesta_cifrada[len(nonce):])
        print(f"Servidor: {respuesta_descifrada.decode()}")
    
    cliente_socket.close()
    
if __name__ == "__main__":
    cliente()
