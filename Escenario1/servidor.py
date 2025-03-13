import socket
import os
import struct
import threading
from Cryptodome.Cipher import ChaCha20, Salsa20

def generar_clave(algoritmo):
    if algoritmo == 'salsa20':
        return os.urandom(32)  # Salsa20 usa una clave de 32 bytes
    elif algoritmo == 'chacha20':
        return os.urandom(32)  # ChaCha20 usa una clave de 32 bytes
    else:
        raise ValueError("Algoritmo no soportado")

def manejar_cliente(cliente_socket, clave, algoritmo):
    while True:
        try:
            mensaje_cifrado = cliente_socket.recv(1024)
            if not mensaje_cifrado:
                break
            
            if algoritmo == 'salsa20':
                nonce = mensaje_cifrado[:8]
                cifrador = Salsa20.new(key=clave, nonce=nonce)
            else:
                nonce = mensaje_cifrado[:12]
                cifrador = ChaCha20.new(key=clave, nonce=nonce)
            
            mensaje_descifrado = cifrador.decrypt(mensaje_cifrado[len(nonce):])
            print(f"Cliente: {mensaje_descifrado.decode()}")
            
            respuesta = input("Servidor: ")
            nuevo_nonce = os.urandom(8 if algoritmo == 'salsa20' else 12)
            cifrador = Salsa20.new(key=clave, nonce=nuevo_nonce) if algoritmo == 'salsa20' else ChaCha20.new(key=clave, nonce=nuevo_nonce)
            mensaje_enviado = nuevo_nonce + cifrador.encrypt(respuesta.encode())
            cliente_socket.send(mensaje_enviado)
        except Exception as e:
            print(f"Error: {e}")
            break

    cliente_socket.close()

def servidor():
    servidor_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor_socket.bind(("128.0.0.1", 5555))
    servidor_socket.listen(1)
    print("Esperando conexión...")
    
    cliente_socket, _ = servidor_socket.accept()
    print("Cliente conectado.")
    
    algoritmo = cliente_socket.recv(1024).decode()
    print(f"Algoritmo seleccionado: {algoritmo}")
    
    clave = generar_clave(algoritmo)
    print("Clave generada y enviada al cliente.")
    cliente_socket.send(clave)
    
    manejar_cliente(cliente_socket, clave, algoritmo)
    servidor_socket.close()
    
if __name__ == "__main__":
    servidor()