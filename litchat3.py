import base64
import ssl
import sys
import socket
import time
import threading
import re

IRC_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def encode(input_str, password):
    joined = "".join([str(ord(char)).zfill(3) for char in input_str])
    encrypted_num = int(joined + "0") * int("".join([str(ord(char)).zfill(2) for char in password]))
    encoded_str = base64.b64encode(str(encrypted_num).encode("ascii")).decode("ascii")
    return encoded_str[::-1]

def decode(encoded_str, password):
    decoded_num = int(base64.b64decode(encoded_str[::-1]).decode("ascii"))
    divided = str(decoded_num // int("".join([str(ord(char)).zfill(2) for char in password])))[:-1]
    decrypted = "".join([chr(int(divided[i:i+3])) for i in range(0, len(divided), 3)])
    
    # Check if decrypted message contains any non-ASCII characters
    if re.search(r'[^\x00-\x7F]', decrypted):
        raise ValueError('Decrypted message is not valid')
        
    return decrypted

def recv_messages(sock, password, channel, nickname):
    while True:
        try:
            data = sock.recv(4096).decode()
        except ssl.SSLWantReadError:
            # No data available yet, wait and try again
            time.sleep(0.1)
            continue
        parts = data.split(" ")
        if len(parts) >= 4 and parts[1] == "PRIVMSG":
            sender = parts[0].split("!")[0][1:]
            message = " ".join(parts[3:])[1:]
            try:
                decrypted_message = decode(message, password)
                # Check if decrypted message makes sense
                if re.search(r"\b\w{1,}\b", decrypted_message):
                    print(f"<{sender}> {decrypted_message}")
            except (base64.binascii.Error, ValueError):
                # Skip messages that cannot be properly decoded
                pass
        else:
            print(data)




def send_messages(sock, password, channel, nickname):
    while True:
        user_input = input().strip()
        if user_input == "/quit":
            # Quit IRC
            sock.send(f"QUIT :Leaving\r\n".encode())
            sock.close()
            sys.exit()
        elif user_input.startswith("/send"):
            # Extract filename and recipient nickname from command
            parts = user_input.split(" ")
            if len(parts) != 3:
                print("Invalid command. Usage: /send <filename> <nickname>")
            else:
                filename = parts[1]
                recipient = parts[2]

                # Get recipient's IP address and DCC port
                sock.send(f"WHOIS {recipient}\r\n".encode())
                data = ""
                while True:
                    data += sock.recv(4096).decode()
                    if "WHOIS" in data:
                        break
                match = re.search(f"{recipient} \S+ \S+ \S+ \S+ (\S+) (\d+) (\S+)", data)
                if not match:
                    print(f"Could not find user {recipient}")
                    continue
                address = match.group(1)
                port = int(match.group(2))

                # Initiate DCC file transfer
                dcc_transfer(sock, filename, address, port)
        else:
            # Send message to channel
            encrypted_message = encode(user_input, password)
            sock.send(f"PRIVMSG {channel} :{encrypted_message}\r\n".encode())
            print(f"[{nickname}] {user_input}")


def dcc_transfer(sock, filename, address, port):
    # Request file transfer via DCC
    sock.send(f"DCC SEND {filename} {address} {port} 0 0\r\n".encode())

    # Accept file transfer
    dcc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dcc_sock.bind(('0.0.0.0', port))
    dcc_sock.listen(1)
    dcc_conn, dcc_addr = dcc_sock.accept()
    with open(filename, "wb") as f:
        while True:
            data = dcc_conn.recv(4096)
            if not data:
                break
            f.write(data)
    dcc_conn.close()


def main():
    # Get user input for username and password
    username = input("Enter your username/nickname for IRC: ")
    password = input("Enter the encryption password: ")

    # IRC configuration
    server = "ircd.chat"  # IRC server hostname
    port = 6697  # IRC server port
    channel = "#litten"  # IRC channel name
    nickname = username  # Set IRC nickname to user input

        # Connect to IRC server
    context = ssl.create_default_context()
    IRC_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    IRC_socket = context.wrap_socket(IRC_socket, server_hostname=server)
    IRC_socket.connect((server, port))
    IRC_socket.send(f"NICK {nickname}\r\n".encode())
    IRC_socket.send(f"USER {nickname} {nickname} {nickname} :Python IRC\r\n".encode())
    IRC_socket.send(f"JOIN {channel}\r\n".encode())
    IRC_socket.setblocking(False)  # Set socket to non-blocking mode

    # Start the threads for receiving and sending messages
    recv_thread = threading.Thread(target=recv_messages, args=(IRC_socket, password, channel, nickname))
    send_thread = threading.Thread(target=send_messages, args=(IRC_socket, password, channel, nickname))

    # Run the threads
    recv_thread.start()
    send_thread.start()

    # Join the threads, so the program doesn't exit until both threads finish
    recv_thread.join()
    send_thread.join()

if __name__ == '__main__':
    main()
