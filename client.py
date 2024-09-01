import threading, socket, json, sys
import dearpygui.dearpygui as dpg
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

# python3 client.py [HOST] [PORT] [USERNAME]

class Crypto:
    def encrypt(self, message, public_key_str):
        public_key = self.load_public_key(public_key_str)
        return public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).hex()
    
    def load_public_key(self, public_key_str):
        public_key_bytes = bytes.fromhex(public_key_str)
        return serialization.load_der_public_key(public_key_bytes)

class Client:
    def __init__(self, host, port):
        self.host       = host
        self.port       = port
        self.socket     = None
        self.prefix     = ""
        self.username   = ""
        self.messages   = []
        self.public_key = None
        self.crypto     = Crypto()

    def load_config(self):
        with open("Client/config.json", "r") as f:
            config = json.load(f)
            self.prefix   = config["prefix"]
            self.username = sys.argv[3]

    def receive(self):
        while True:
            data = self.socket.recv(1024)
            if not data:
                break
            try:
                if "SPLASH" in data.decode():
                    # print(data.decode())
                    self.update_messages(data.decode()[6:])

                data_ = eval(data.decode())
                if data_[0] == "PUBLIC-KEY":
                    self.public_key = data_[1]
                    continue
                self.update_messages(data_[1])
            except Exception as e:
                print(f"Error during data evaluation: {e}")

    def send(self, message, type="MESSAGE"):
        if type == "IDENTIFY":
            message = "('{}', '{}')".format(type, self.username)
        elif type == "DISCONNECT":
            message = "('{}', '{}')".format(type, self.username)
        else:
            encrypted_message = self.crypto.encrypt(message.encode(), self.public_key)
            message = "('{}', '{}', '{}')".format(type, self.username, encrypted_message)
        try:
            self.socket.send(message.encode())
        except Exception as e:
            print(f"Error during sending message: {e}")

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((str(self.host), int(self.port)))
        self.send(self.username, "IDENTIFY")
        threading.Thread(target=self.receive).start()

    def run(self):
        self.load_config()
        self.connect()

class Gui(Client):
    def __init__(self, host, port):
        super().__init__(host, port)
        threading.Thread(target=self.window).start()
        self.messages = []
        self.previous = ""

    def window(self):
        dpg.create_context()
        dpg.create_viewport()
        dpg.setup_dearpygui()

        with dpg.window(label="SillyChatApp", width=1000, height=500):
            dpg.add_input_text(tag="big_text_box", multiline=True, readonly=True, width=1000, height=400, default_value="Please wait 5 seconds to connect to the server...")
            with dpg.group(horizontal=True):
                dpg.add_input_text(tag="input_box", width=900, height=40, hint="Type here...")
                dpg.add_button(label="Submit", width=80, height=40, callback=self.sendm)

        dpg.show_viewport()
        dpg.start_dearpygui()
        dpg.destroy_context()

    def sendm(self):
        message = dpg.get_value("input_box")
        if message == "{}help".format(self.prefix):
            self.update_messages("Available commands: \n{}\n{}".format("{}exit".format(self.prefix), "{}help".format(self.prefix)))
            return
        elif message == "{}exit".format(self.prefix):
            threading.Thread(target=self.send, args=(message, "DISCONNECT")).start()
            exit()
        self.previous = message
        dpg.set_value("input_box", "")
        super().send(message)


    def update_messages(self, message):
        self.messages.append(message)
        text = "{}".format("\n".join(self.messages))
        dpg.set_value("big_text_box", text)

def main():
    client = Gui(sys.argv[1], int(sys.argv[2]))
    client.run()

if __name__ == "__main__":
    main()