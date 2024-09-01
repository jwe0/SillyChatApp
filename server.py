import threading, socket, json, time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

class Crypto:
    def gen_pair(self):
        key_size = 2048
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def decrypt(self, message, private_key):
        message = bytes.fromhex(message)
        return private_key.decrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()
    

class server:
    def __init__(self, host, port):
        self.host   = host
        self.port   = port
        self.socket = None
        self.users  = []
        self.names  = []
        self.splash = self.load_splash()
        self.crypto = Crypto()
        self.pair   = self.crypto.gen_pair()

    def load_splash(self):
        with open("Server/splash.txt", "r") as f:
            return f.read()

    def hash_pub(self, pub):
        public_key_bytes = pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_key_bytes.hex()

    def verify(self, source):
        if self.hash_pub(self.pair[1]) == source:
            return True
        return False

    def broadcast(self, message, sender):
        for user in self.users:
            user.send(message)

    def format_message(self, tuple_data):
        message_type = tuple_data[0]
        if message_type == "IDENTIFY":
            if tuple_data[1] in self.names:
                print(self.users)
                self.users.pop(-1)
                print(self.users)
                return "Username already taken."
            self.names.append(str(tuple_data[1]))
            return "('IDENTIFY', '{}')".format("[{}] Has joined the server.".format(tuple_data[1]))
        elif message_type == "MESSAGE":
            username     = tuple_data[1] 
            message      = tuple_data[2]
            print(message)
            message_ = self.crypto.decrypt(message, self.pair[0])
            print(message_)
            return "('MESSAGE', '{}')".format("[{}] : {}".format(username, message_))
        elif message_type == "DISCONNECT":
            username = tuple_data[1]
            index = self.names.index(username)
            self.users.pop(index)
            self.names.pop(index)
            return "('DISCONNECT', '{}')".format("[{}] Has left the server.".format(username))

    def handle_client(self, client_socket, client_address):
        client_socket.send("SPLASH\n{}".format(self.splash).encode())
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            data = eval(data.decode())
            message = self.format_message(data).encode()
            if message == "Username already taken.":
                client_socket.send(message)
                client_socket.close()
                break
            elif message == "Signature verification failed.":
                client_socket.send(message)
                client_socket.close()
                break
            else:
                self.broadcast(message, data[1])
                print(message.decode())

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        while True:
            client_socket, client_address = self.socket.accept()
            if not client_socket:
                break
            self.users.append(client_socket)
            hash = str(self.hash_pub(self.pair[1]))
            print(hash)
            client_socket.send("('{}', '{}')".format("PUBLIC-KEY", hash).encode())
            time.sleep(5)
            threading.Thread(target=self.handle_client, args=(client_socket, client_address)).start()

    def run(self):
        self.connect()

if __name__ == "__main__":
    with open("Server/config.json", "r") as f:
        config = json.load(f)
        host = config["host"]
        port = config["port"]
    server_ = server(host, port)
    server_.run()