import socket

# I have no idea what this does
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# This is the IP address of the server that we are connecting to
client.connect(('0.tcp.jp.ngrok.io', 12096))

# This is the message that we are sending to the server
print(client.recv(1024).decode('utf-8'))
client.send("Hey Server".encode('utf-8'))