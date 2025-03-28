import socket, threading
from torpy import TorClient
from kyber_py.kyber import Kyber512


class GenesisCatacomb:

    def __init__(self, nickname, port=5000):
        
        self.nickname = nickname
        self.port = port
        self.pk, self.sk = Kyber512.keygen() # public and secret key
        self.tor_client = None               # tor client


    def connect_tor(self):
        # create tor connection
        self.tor_client = TorClient()
        self.tor_session = self.tor_client.get_guard().create_circuit()
        print(f"{self.nickname} connected to TOR")

    
    def send_message(self, recip_ip, recip_port, message, recip_pk):
        # encrypt message with kyber and send (sender)
        shared_secret, ciphertext = Kyber512.encaps(recip_pk)
        payload = ciphertext + b"||" + message.encode('utf-8')

        if self.tor_client:
            with self.tor_session.create_socket() as sock:
                sock.connect((recip_ip, recip_port))
                sock.sendall(payload)

        else:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((recip_ip, recip_port))
                sock.sendall(payload)

        print(f"Sent: {message}")


    def receive_message(self):
        # decrypt message and receive (receiver)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(('0.0.0.0', self.port))
            sock.listen(1)

            while True:
                conn, addr = sock.accept()

                with conn:
                    data = conn.recv(4096)
                    ciphertext, message = data.split(b"||")
                    shared_secret = Kyber512.decaps(self.sk, ciphertext)
                    
                    print(f"Received: {message.decode('utf-8')} (from {addr})")


    def start(self):
        print(f"Starting {self.nickname}'s Catacomb on port {self.port}...")
        # self.connect_tor()
        threading.Thread(target=self.receive_message, daemon=True).start()
        return self.pk
    

if __name__ == "__main__":

    # sender
    sender = GenesisCatacomb("Heremolaos")
    sender_pk = sender.start()

    # receiver
    receiver = GenesisCatacomb("Voldemor", 5001)
    receiver_pk = receiver.start()

    input("Press enter after both are running...")
    sender.send_message('127.0.0.1', 5001, "Resistance is alive!!", receiver_pk)