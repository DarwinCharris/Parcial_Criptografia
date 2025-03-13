import os
import time
from Cryptodome.Cipher import Salsa20, ChaCha20

def medir_tiempo(algoritmo, clave, mensaje, nonce):
    # Cifrado
    inicio = time.perf_counter()
    cifrador = Salsa20.new(key=clave, nonce=nonce) if algoritmo == 'salsa20' else ChaCha20.new(key=clave, nonce=nonce)
    mensaje_cifrado = cifrador.encrypt(mensaje)
    fin = time.perf_counter()
    tiempo_cifrado = fin - inicio

    # Descifrado
    inicio = time.perf_counter()
    descifrador = Salsa20.new(key=clave, nonce=nonce) if algoritmo == 'salsa20' else ChaCha20.new(key=clave, nonce=nonce)
    mensaje_descifrado = descifrador.decrypt(mensaje_cifrado)
    fin = time.perf_counter()
    tiempo_descifrado = fin - inicio

    #Verificación de cifrado exitoso
    assert mensaje == mensaje_descifrado
    return tiempo_cifrado, tiempo_descifrado

# Parámetros de la prueba
iteraciones = 10000
tamaño_mensaje = 1024
clave = os.urandom(32) #32B

# Variables para almacenar los tiempos acumulados
suma_cifrado_salsa, suma_descifrado_salsa = 0, 0
suma_cifrado_chacha, suma_descifrado_chacha = 0, 0
mCifradosSalsa, mDescifradosSalsa = [], []
mCifradosChacha, mDescifradosChacha= [],[]

for _ in range(iteraciones):
    mensaje = os.urandom(tamaño_mensaje) 
    nonce_salsa = os.urandom(8)  # Salsa20 nonce de 8 bytes
    nonce_chacha = os.urandom(12)  # ChaCha20 nonce de 12 bytes

    # Medir tiempos para Salsa20
    cifrado_salsa, descifrado_salsa = medir_tiempo('salsa20', clave, mensaje, nonce_salsa)
    mCifradosSalsa.append(cifrado_salsa)
    mDescifradosSalsa.append(descifrado_salsa)
    suma_cifrado_salsa += cifrado_salsa
    suma_descifrado_salsa += descifrado_salsa

    # Medir tiempos para ChaCha20
    cifrado_chacha, descifrado_chacha = medir_tiempo('chacha20', clave, mensaje, nonce_chacha)
    mCifradosChacha.append(cifrado_chacha)
    mDescifradosChacha.append(descifrado_chacha)
    suma_cifrado_chacha += cifrado_chacha
    suma_descifrado_chacha += descifrado_chacha

# Promedios
prom_cifrado_salsa = suma_cifrado_salsa / iteraciones
prom_descifrado_salsa = suma_descifrado_salsa / iteraciones
prom_cifrado_chacha = suma_cifrado_chacha / iteraciones
prom_descifrado_chacha = suma_descifrado_chacha / iteraciones

#Resultados
print(f"Salsa20 - Cifrado: {prom_cifrado_salsa:.8f} s | Descifrado: {prom_descifrado_salsa:.8f} s")
print(f"ChaCha20 - Cifrado: {prom_cifrado_chacha:.8f} s | Descifrado: {prom_descifrado_chacha:.8f} s")

if prom_cifrado_salsa < prom_cifrado_chacha:
    print("Salsa20 es más rápido para cifrar.")
else:
    print("ChaCha20 es más rápido para cifrar.")

if prom_descifrado_salsa < prom_descifrado_chacha:
    print("Salsa20 es más rápido para descifrar.")
else:
    print("ChaCha20 es más rápido para descifrar.")

import matplotlib.pyplot as plt

def graficar_lineas(a, b, c, d):
    plt.figure(figsize=(12, 10))

    # Gráfico 1: Tiempos de cifrado
    plt.subplot(2, 1, 1)
    plt.plot(a, color='red', label='Salsa20 - Cifrado', alpha=0.7)
    plt.plot(b, color='blue', label='ChaCha20 - Cifrado', alpha=0.7)
    plt.xlabel('')
    plt.ylabel('Tiempo')
    plt.title('Comparación de Tiempos de Cifrado')
    plt.legend()
    plt.grid(True)

    # Gráfico 2: Tiempos de descifrado
    plt.subplot(2, 1, 2)
    plt.plot(c, color='red', label='Salsa20 - Descifrado', alpha=0.7)
    plt.plot(d, color='blue', label='ChaCha20 - Descifrado', alpha=0.7)
    plt.xlabel('')
    plt.ylabel('Tiempo')
    plt.title('Comparación de Tiempos de Descifrado')
    plt.legend()
    plt.grid(True)

    plt.tight_layout()
    plt.show()

graficar_lineas(mCifradosSalsa, mCifradosChacha, mDescifradosSalsa, mDescifradosChacha)





