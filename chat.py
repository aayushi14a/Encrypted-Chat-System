import sys
import socket
import threading
import datetime
import os
import random
import logging
import traceback

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class RSA:
    @staticmethod
    def gcd(a, b):
        while b != 0:
            a, b = b, a % b
        return a

    @staticmethod
    def multiplicative_inverse(e, phi):
        d = 0
        x1 = 0
        x2 = 1
        y1 = 1
        temp_phi = phi
        while e > 0:
            temp1 = temp_phi // e
            temp2 = temp_phi - temp1 * e
            temp_phi = e
            e = temp2
            x = x2 - temp1 * x1
            y = d - temp1 * y1
            x2 = x1
            x1 = x
            d = y1
            y1 = y
        if temp_phi == 1:
            return d + phi

    @staticmethod
    def is_prime(num):
        if num == 2:
            return True
        if num < 2 or num % 2 == 0:
            return False
        for n in range(3, int(num**0.5) + 1, 2):
            if num % n == 0:
                return False
        return True

    @staticmethod
    def generate_key_pair(p, q):
        if not (RSA.is_prime(p) and RSA.is_prime(q)):
            raise ValueError('Both numbers must be prime.')
        elif p == q:
            raise ValueError('p and q cannot be equal')
        n = p * q
        phi = (p - 1) * (q - 1)
        
        e = random.randrange(1, phi)
        g = RSA.gcd(e, phi)
        while g != 1:
            e = random.randrange(1, phi)
            g = RSA.gcd(e, phi)

        d = RSA.multiplicative_inverse(e, phi)
        return ((e, n), (d, n))

    @staticmethod
    def encrypt(public_key, plaintext):
        key, n = public_key
        cipher = [pow(ord(char), key, n) for char in plaintext]
        return cipher

    @staticmethod
    def decrypt(private_key, ciphertext):
        key, n = private_key
        plain = [chr(pow(char, key, n)) for char in ciphertext]
        return ''.join(plain)

def send_data(conn, data):
    try:
        conn.send(f"~{data}~".encode())
        logging.debug(f"Sent data: {data}")
    except Exception as e:
        logging.error(f"Error sending data: {e}")
        raise

def receive_data(conn):
    data = ""
    try:
        while True:
            chunk = conn.recv(1024).decode()
            if not chunk:
                raise ConnectionError("Connection closed by remote host")
            data += chunk
            if data.endswith("~"):
                break
        received_data = data.strip("~")
        logging.debug(f"Received data: {received_data}")
        return received_data
    except Exception as e:
        logging.error(f"Error receiving data: {e}")
        raise

def key_exchange(conn, is_server):
    try:
        public, private = RSA.generate_key_pair(17, 23)
        logging.debug(f"{'Server' if is_server else 'Client'} generated keys: public={public}, private={private}")
        
        if is_server:
            # Receive client's public key
            client_public_key_str = receive_data(conn)
            client_public_key = tuple(map(int, client_public_key_str.split(',')))
            logging.info("* Client's Public Key received *")
            
            # Send server's public key
            send_data(conn, f"{public[0]},{public[1]}")
            logging.info("* Public Key sent *")
        else:
            # Send client's public key
            send_data(conn, f"{public[0]},{public[1]}")
            logging.info("* Public Key sent *")
            
            # Receive server's public key
            server_public_key_str = receive_data(conn)
            client_public_key = tuple(map(int, server_public_key_str.split(',')))
            logging.info("* Server's Public Key received *")

        # Verify encryption
        test_message = f"{'Server' if is_server else 'Client'}:abcdefghijklmnopqrstuvwxyz"
        encrypted_test = RSA.encrypt(client_public_key, test_message)
        send_data(conn, str(encrypted_test))
        logging.debug(f"Sent encrypted test message: {encrypted_test}")
        
        # Receive and decrypt test message
        received_test = receive_data(conn)
        decrypted_test = RSA.decrypt(private, eval(received_test))
        logging.debug(f"Received and decrypted test: {decrypted_test}")
        
        expected_test = "Client:abcdefghijklmnopqrstuvwxyz" if is_server else "Server:abcdefghijklmnopqrstuvwxyz"
        if decrypted_test != expected_test:
            logging.error("* Encryption verification failed *")
            send_data(conn, "ABORT")
            return None, None
        
        if is_server:
            send_data(conn, "OK")
        else:
            verification_result = receive_data(conn)
            if verification_result != "OK":
                logging.error("* Server couldn't verify encryption *")
                return None, None
        
        logging.info("* Encryption verified successfully *")
        return private, client_public_key
    except Exception as e:
        logging.error(f"* ERROR during key exchange: {str(e)} *")
        logging.error(traceback.format_exc())
        return None, None

def Server(host, port):
    port = int(port)
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((host, port))
        server.listen(5)
        logging.info("* Waiting for partner to join conversation... *")
        conn, client_addr = server.accept()
        logging.info(f"* Client connected from {client_addr} *")
    except Exception as e:
        logging.error(f"* ERROR: {e} *")
        return

    private, client_public_key = key_exchange(conn, True)
    if not private or not client_public_key:
        connClose(conn)
        return

    logging.info("\n* Connected to chat *")
    print("1. Type your messages below and hit Enter to send")
    print("2. Type 'file()' and hit Enter to send a file in the current directory")
    print("3. Type 'quit()' and hit Enter to leave the conversation\n")

    ReadThread = Thread_Manager('read', conn, private, client_public_key)
    WriteThread = Thread_Manager('write', conn, private, client_public_key)
    ReadThread.start()
    WriteThread.start()
    ReadThread.join()
    logging.info("\n* Your partner has left the conversation. Press any key to quit... *")
    WriteThread.stopWrite()
    WriteThread.join()
    connClose(conn)

def Client(host, port):
    port = int(port)
    logging.info("\n* Connecting to server... *")
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))

    private, server_public_key = key_exchange(client, False)
    if not private or not server_public_key:
        connClose(client)
        return

    logging.info("\n* Connected to chat *")
    print("1. Type your messages below and hit Enter to send")
    print("2. Type 'file()' and hit Enter to send a file in the current directory")
    print("3. Type 'quit()' and hit Enter to leave the conversation\n")

    ReadThread = Thread_Manager('read', client, private, server_public_key)
    WriteThread = Thread_Manager('write', client, private, server_public_key)
    ReadThread.start()
    WriteThread.start()
    ReadThread.join()
    logging.info("\n* Your partner has left the conversation. Press any key to quit... *")
    WriteThread.stopWrite()
    WriteThread.join()
    connClose(client)

def connClose(conn):
    try:
        logging.info("* Closing all sockets and exiting... *")
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()
    except:
        pass

class Thread_Manager(threading.Thread):
    def __init__(self, action, conn, private, public):
        threading.Thread.__init__(self)
        self.action = action.lower()
        self.conn = conn
        self.dowrite = True
        self.exitcode = 'quit()'
        self.public = public
        self.private = private

    def run(self):
        if self.action == 'read':
            self.read()
        elif self.action == "file":
            self.file()
        else:
            self.write()

    def stopWrite(self):
        self.dowrite = False

    def read(self):
        global doRead
        while doRead:
            try:
                data = receive_data(self.conn)
                if data == "[]":
                    doRead = False
                elif data == "ABORT":
                    logging.info("\n* Partner aborted the connection *")
                    doRead = False
                else:
                    decrypted_data = RSA.decrypt(self.private, eval(data))
                    if decrypted_data.startswith("FILE:"):
                        _, filename, file_content = decrypted_data.split(":", 2)
                        with open(f"received_{filename}", "w") as f:
                            f.write(file_content)
                        logging.info(f"\nReceived file: received_{filename}")
                    else:
                        print(f"\nPartner: {decrypted_data}")
            except Exception as e:
                logging.error(f"Error in read thread: {e}")
                doRead = False

    def write(self):
        while self.dowrite:
            data = input()
            if data.lower() == self.exitcode:
                send_data(self.conn, "[]")
                self.dowrite = False
            elif data.lower() == "file()":
                self.file()
            else:
                try:
                    encrypted_data = RSA.encrypt(self.public, data)
                    send_data(self.conn, str(encrypted_data))
                except Exception as e:
                    logging.error(f"Error sending message: {e}")
                    self.dowrite = False

    def file(self):
        filename = input("Enter filename: ")
        if os.path.isfile(filename):
            try:
                with open(filename, 'r') as f:
                    data = f.read()
                encrypted_data = RSA.encrypt(self.public, f"FILE:{filename}:{data}")
                send_data(self.conn, str(encrypted_data))
                logging.info(f"* File {filename} sent *")
            except Exception as e:
                logging.error(f"Error sending file: {e}")
        else:
            logging.warning(f"* File {filename} does not exist *")

if __name__ == "__main__":
    TESTING = True
    print("")
    print("------------------------------------------------------")
    print(" ENCRYPTED CHAT v1.0 ")
    print("------------------------------------------------------")

    if TESTING:
        host = 'localhost'
        port = 1337
    else:
        if (len(sys.argv) < 3):
            print("\nUsage: python encryptedChat.py <hostname/IP> <port>\n")
            input("Press any key to quit")
            exit(0)
        host = sys.argv[1]
        port = sys.argv[2]

    doRead = True

    try:
        Client(host, port)
    except Exception as e:
        if TESTING:
            logging.error(f"Client error: {e}")
            logging.error(traceback.format_exc())
        logging.info("* Server was not found. Creating server... *")
        try:
            Server(host, port)
        except Exception as e:
            if TESTING:
                logging.error(f"Server error: {e}")
                logging.error(traceback.format_exc())
            logging.error("* ERROR creating server *")

    logging.info("\n* Exiting... Goodbye! *")