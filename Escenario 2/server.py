import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def setup_cipher(mode, key, iv = None):
    if mode == 'ECB':
        return AES.new(key, AES.MODE_ECB)
    elif mode == 'CBC':
        return AES.new(key, AES.MODE_CBC, iv)
    elif mode == 'CTR':
        return AES.new(key, AES.MODE_CTR, nonce=iv)
    
def xor_bytes(data, key):
    """Realiza XOR entre cada byte de data y key (se repite key si es necesario)."""
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def encrypt_whitening(cipher, whitening_pre, whitening_post, mensaje):
    """
    Aplica key whitening utilizando 2 llaves adicionales (16 bytes cada una):
      - Pre-whitening: XOR del mensaje (con padding) con whitening_pre.
      - Se cifra el resultado.
      - Post-whitening: XOR del ciphertext con whitening_post.
    """
    padded = pad(mensaje.encode('utf-8'), AES.block_size)
    pre_whitened = xor_bytes(padded, whitening_pre)
    encrypted = cipher.encrypt(pre_whitened)
    final_ciphertext = xor_bytes(encrypted, whitening_post)
    return final_ciphertext


def decrypt_whitening(cipher, whitening_pre, whitening_post, ciphertext):
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

def encrypt_key(key_to_encrypt, key): #Metodo para encriptar llaves adicionales
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(key_to_encrypt, AES.block_size))
    return cipher.iv + ciphertext

def generate_key():
    return get_random_bytes(32)

def start_server(host='10.20.17.46', port=65432):

    ready_to_continue = False

    with open('key.bin', 'rb') as key_file:
        shared_key = key_file.read()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))

        server_socket.listen()
        print(f'Socket iniciado en {host}:{port}')

        conn, addr = server_socket.accept()
        with conn:
            print(f'{addr} se ha conectado')

            data = conn.recv(1024)
            parametros_iniciales = data.decode('utf-8').split(',')
            print(parametros_iniciales)

            additional_keys = []
            if parametros_iniciales[1] == 'cifrado doble':
                additional_keys.append(generate_key())
            elif parametros_iniciales[1] == 'cifrado triple':
                additional_keys.append(generate_key())
                additional_keys.append(generate_key())
            elif parametros_iniciales[1] == 'blanqueamiento de llave':
                additional_keys.append(get_random_bytes(32))
                additional_keys.append(get_random_bytes(32))

            for key in additional_keys:
                encrypted_key = encrypt_key(key, shared_key) 
                conn.sendall(encrypted_key)
                print('llave adicional enviada.')

            iv = None
            if parametros_iniciales[0] == 'CBC':
                iv = get_random_bytes(16)
            elif parametros_iniciales[0] == 'CTR':
                iv = get_random_bytes(8)

            if parametros_iniciales[0] in ['CBC', 'CTR']:
                conn.sendall(iv)

            ready_to_continue = True

            while True and ready_to_continue:
                ciphertext = conn.recv(1024)
                if not ciphertext:
                    break
                print(f'valor del mensaje cifrado: {ciphertext.hex()}')
                cipher = setup_cipher(parametros_iniciales[0], shared_key, iv)
                cipher2 = setup_cipher(parametros_iniciales[0], additional_keys[0], iv) if parametros_iniciales[1] == 'cifrado doble' or parametros_iniciales[1] == 'cifrado triple' else None
                cipher3 = setup_cipher(parametros_iniciales[0], additional_keys[1], iv) if parametros_iniciales[1] == 'cifrado triple' else None
                
                if parametros_iniciales[1] == 'ninguna':
                    mensaje = decrypt_mensaje(cipher, ciphertext)
                elif parametros_iniciales[1] == 'cifrado doble':
                    mensaje = decrypt_double(cipher, cipher2, ciphertext)
                elif parametros_iniciales[1] == 'cifrado triple':
                    mensaje = decrypt_triple(cipher, cipher2, cipher3, ciphertext)
                elif parametros_iniciales[1] == 'blanqueamiento de llave':
                    mensaje = decrypt_whitening(cipher, additional_keys[0], additional_keys[1], ciphertext)
                print(f'mensaje del cliente: {mensaje}')
                print(f'valor del mensaje: {mensaje.encode('utf-8').hex()}')

                
                cipher_respuesta = setup_cipher(parametros_iniciales[0],shared_key,iv)
                cipher_respuesta2 = setup_cipher(parametros_iniciales[0],additional_keys[0],iv) if parametros_iniciales[1] == 'cifrado doble' or parametros_iniciales[1] == 'cifrado triple' else None
                cipher_respuesta3 = setup_cipher(parametros_iniciales[0],additional_keys[1],iv) if parametros_iniciales[1] == 'cifrado triple' else None
                respuesta = input('Respuesta a cliente: ')
                if parametros_iniciales[1] == 'cifrado doble':
                    mensaje_encriptado = encrypt_double(cipher_respuesta, cipher_respuesta2, respuesta)
                elif parametros_iniciales[1] == 'cifrado triple':
                    mensaje_encriptado = encrypt_triple(cipher_respuesta, cipher_respuesta2, cipher_respuesta3, respuesta)
                elif parametros_iniciales[1] == 'blanqueamiento de llave':
                    mensaje_encriptado = encrypt_whitening(cipher_respuesta, additional_keys[0], additional_keys[1], respuesta)
                else:
                    mensaje_encriptado = encrypt_mensaje(cipher_respuesta, respuesta)
                conn.sendall(mensaje_encriptado)

if __name__=='__main__':
    start_server()