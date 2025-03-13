from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def generate_key():
    return get_random_bytes(32)

def save_key(key, filename='key.bin'):
    with open(filename, 'wb') as key_file:
        key_file.write(key)
    print('llave guardada.')

if __name__ == '__main__':
    key = generate_key()
    save_key(key)