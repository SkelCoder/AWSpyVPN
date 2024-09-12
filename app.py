import socket
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt

SERVER_IP = '0.0.0.0'
SERVER_PORT = 12345
PASSWORD = b"securepassword"
BUFFER_SIZE = 4096

def generate_key(password, salt):
    return scrypt(password, salt, 16, N=2**14, r=8, p=1)

def create_cipher(key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return cipher, iv

def handle_client(client_socket):
    salt = get_random_bytes(16)
    client_socket.send(salt)
    
    key = generate_key(PASSWORD, salt)
    
    cipher, iv = create_cipher(key)
    client_socket.send(iv)
    print(f"Новое подключение: {client_socket.getpeername()}")

    while True:
        try:
            data = client_socket.recv(BUFFER_SIZE)
            if not data:
                break

            decrypted_data = cipher.decrypt(data)
            print(f"Получено от клиента: {decrypted_data}")

            response = b"Принято"
            encrypted_response = cipher.encrypt(response)
            client_socket.send(encrypted_response)
        except Exception as e:
            print(f"Ошибка: {e}")
            break

    client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((SERVER_IP, SERVER_PORT))
    server.listen(5)
    print(f"Сервер запущен на {SERVER_IP}:{SERVER_PORT}")

    while True:
        client_socket, addr = server.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    start_server()
