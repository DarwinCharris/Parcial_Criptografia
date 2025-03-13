import socket 
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad

def load_key(filename='key.bin'):
    with open(filename, 'rb') as key_file:
        return key_file.read()
    
def setup_cipher(mode, key, iv):
    if mode == "ECB":
        return AES.new(key, AES.MODE_ECB)
    elif mode == "CBC":
        return AES.new(key, AES.MODE_CBC, iv)
    elif mode == "CTR":
        return AES.new(key, AES.MODE_CTR, nonce=iv)
    

def recvall(sock, n):
    """Recibe exactamente n bytes del socket."""
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            break
        data += packet
    return data

def xor_bytes(data, key):
    """Realiza XOR entre cada byte de data y key (se repite key si es necesario)."""
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])


def encrypt_whitening(cipher, whitening_pre, whitening_post, mensaje):
    """
    Aplica key whitening utilizando 2 llaves adicionales:
      1. Pre-whitening: XOR del mensaje (con padding) con whitening_pre.
      2. Se cifra el resultado.
      3. Post-whitening: XOR del ciphertext con whitening_post.
    """
    padded = pad(mensaje.encode('utf-8'), AES.block_size)
    pre_whitened = xor_bytes(padded, whitening_pre)
    encrypted = cipher.encrypt(pre_whitened)
    final_ciphertext = xor_bytes(encrypted, whitening_post)
    return final_ciphertext


def decrypt_whitening(cipher, whitening_pre, whitening_post, ciphertext):
    """
    Revierte el key whitening:
      1. Se hace XOR del ciphertext con whitening_post.
      2. Se descifra el resultado.
      3. Se hace XOR del plaintext intermedio con whitening_pre.
      4. Se remueve el padding.
    """
    post_unwhitened = xor_bytes(ciphertext, whitening_post)
    decrypted = cipher.decrypt(post_unwhitened)
    unwhitened = xor_bytes(decrypted, whitening_pre)
    return unpad(unwhitened, AES.block_size).decode('utf-8')
    
def encrypt_mensaje(cipher, mensaje):
    return cipher.encrypt(pad(mensaje.encode('utf-8'), AES.block_size))

def encrypt_double(cipher1, cipher2, mensaje):
    encripted_mensaje1 = cipher1.encrypt(pad(mensaje.encode('utf-8'), AES.block_size))

    return cipher2.encrypt(encripted_mensaje1)

def encrypt_triple(cipher1, cipher2, cipher3, mensaje):
    encripted1 = cipher1.encrypt(pad(mensaje.encode('utf-8'), AES.block_size))
    encripted2 = cipher2.encrypt(encripted1)
    return cipher3.encrypt(encripted2)

def decrypt_triple(cipher1, cipher2, cipher3, ciphertext):
    decrypted1 = cipher3.decrypt(ciphertext)
    decrypted2 = cipher2.decrypt(decrypted1)
    return unpad(cipher1.decrypt(decrypted2), AES.block_size).decode('utf-8')

def decrypt_double(cipher1, cipher2, ciphertext):
    decrypted_mensaje = cipher2.decrypt(ciphertext)

    return unpad(cipher1.decrypt(decrypted_mensaje), AES.block_size).decode('utf-8')

def decrypt_mensaje(cipher, ciphertext):
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')

    
def decrypt_key(encrypted_key, shared_key):
    iv = encrypted_key[:AES.block_size]
    ciphertext = encrypted_key[AES.block_size:]
    cipher = AES.new(shared_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

def start_client(host='10.20.17.46', port=65432):

    ready_to_continue = False

    shared_key = load_key()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket_client:

        socket_client.connect((host, port))
        print(f'conexión a: {host}:{port} establecida.')

        operation_mode = None
        while True:
            operation_mode = input('Escriba el modo de operacion(ECB, CBC o CIR):')
            if operation_mode == 'ECB' or operation_mode == 'CBC' or operation_mode == 'CTR':
                break
        seguridad_adicional = None
        while True:
            seguridad_adicional = input('Escriba la seguridad adicional(ninguna, cifrado doble, cifrado triple o blanqueamiento de llave):')
            if seguridad_adicional == 'ninguna' or seguridad_adicional == 'cifrado doble' or seguridad_adicional == 'cifrado triple' or seguridad_adicional== 'blanqueamiento de llave':
                break

        mensaje_inicial = f'{operation_mode},{seguridad_adicional}'
        socket_client.sendall(mensaje_inicial.encode('utf-8'))

        additional_keys = []
        if seguridad_adicional == "cifrado doble":
            print("Recibiendo llaves adicionales cifradas. ")
            i = 0
            while i < 1:
                i += 1
                encrypted_key = socket_client.recv(1024)
                key = decrypt_key(encrypted_key, shared_key)
                additional_keys.append(key)
                print(f"Llave adicional descifrada. ")
        elif seguridad_adicional == "cifrado triple":
            print("Recibiendo llaves adicionales cifradas. ")
            i = 0
            while i < 2:
                i += 1
                encrypted_key = socket_client.recv(1024)
                key = decrypt_key(encrypted_key, shared_key)
                additional_keys.append(key)
                print(f"Llave adicional descifrada. ")
        elif seguridad_adicional == "blanqueamiento de llave":
            print("Recibiendo llaves de blanqueamiento cifradas.")
            i = 0
            while i < 2:
                i += 1
                encrypted_key = socket_client.recv(1024)
                key = decrypt_key(encrypted_key, shared_key)
                additional_keys.append(key)
                print("Recibiendo llaves de blanqueamiento cifradas.")


        iv = None
        if operation_mode in ["CBC", "CTR"]:
            iv = socket_client.recv(16 if operation_mode == 'CBC' else 8)
            
        ready_to_continue = True

        while True and ready_to_continue:

            cipher = setup_cipher(operation_mode, shared_key, iv)
            cipher2 = setup_cipher(operation_mode, additional_keys[0],iv) if seguridad_adicional == 'cifrado doble' or seguridad_adicional == 'cifrado triple' else None
            cipher3 = setup_cipher(operation_mode, additional_keys[1], iv) if seguridad_adicional == 'cifrado triple' else None

            message = input('Escribir mensaje: ')
            if seguridad_adicional == 'cifrado doble':
                encrypted_mensaje = encrypt_double(cipher, cipher2, message)
            elif seguridad_adicional == 'cifrado triple':
                encrypted_mensaje = encrypt_triple(cipher, cipher2, cipher3, message)
            elif seguridad_adicional == 'blanqueamiento de llave':
                whitening_pre = additional_keys[0]
                whitening_post = additional_keys[1]
                encrypted_mensaje = encrypt_whitening(cipher, whitening_pre, whitening_post, message)
            else:
                encrypted_mensaje = encrypt_mensaje(cipher, message)
            socket_client.sendall(encrypted_mensaje)

            encrypt_response = socket_client.recv(1024)
   
            cipher_respuesta = setup_cipher(operation_mode,shared_key,iv)
            cipher_respuesta2 = setup_cipher(operation_mode,additional_keys[0],iv) if seguridad_adicional == 'cifrado doble' or seguridad_adicional == 'cifrado triple' else None
            cipher_respuesta3 = setup_cipher(operation_mode, additional_keys[1], iv) if seguridad_adicional == 'cifrado triple' else None
            if seguridad_adicional == 'cifrado doble':
                response = decrypt_double(cipher_respuesta, cipher_respuesta2, encrypt_response)
            elif seguridad_adicional == 'cifrado triple':
                response = decrypt_triple(cipher_respuesta, cipher_respuesta2, cipher_respuesta3, encrypt_response)
            elif seguridad_adicional == 'blanqueamiento de llave':
                response = decrypt_whitening(cipher_respuesta, whitening_pre, whitening_post, encrypt_response)
            else:
                response = decrypt_mensaje(cipher_respuesta, encrypt_response)
            print(f'Respuesta del servidor: {response}')

if __name__ == '__main__':
    start_client()
        