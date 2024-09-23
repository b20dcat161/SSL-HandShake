import socket
from module import *
import hashlib

HOST = ''
PORT = 1337
version = ProtocolVersion(3, 0) 
random = Random()
session_id = b''
cipher_suite = b'\x00\x17'
compression_method = b''
connection = SSLConnection()
connection.server_random = random.to_bytes()
def get_data(data):
    global session_id
    # global cipher_suite
    global compression_method
    global connection
    print('stegment: ',data)
    content_type = int.from_bytes(data[:1])
    if(content_type == 22):
        print("recv handshake")
    version = data[1:3]
    print(int.from_bytes(version))
    length=data[3:5]
    print('leng: ',int.from_bytes(length))
    fragment = data[5:]
    print(fragment)
    if (content_type == 22):
        msg_type = int.from_bytes(fragment[:1])
        length =  fragment[1:4]
        print('msg type: ', msg_type)
        body = fragment[4:]
        if msg_type == 1:
            print('type: client hello')
            protocol = body[:2]
            print('protocol: ',protocol)
            random = body[2:34]
            print('client random: ',random)
            connection.client_random = random
            session_id_length = int.from_bytes(body[34:35])
            cipher_suite_index =35 + session_id_length
            session_id = body[35:cipher_suite_index]
            print('session id: ',session_id)
            cipher_suite_length = int.from_bytes(body[cipher_suite_index:cipher_suite_index+2])
            compression_method_index = cipher_suite_index+2+cipher_suite_length
            cipher_suite = body[cipher_suite_index+2:compression_method_index]
            print('cipher suite: ',cipher_suite)
            compression_method_length = int.from_bytes(body[compression_method_index:compression_method_index+1])
            compression_method=body[compression_method_index+1:compression_method_index+1+compression_method_length]
            print('compression_method: ',compression_method)
            
        
def server_hello():
    print("send server hello - session id: ",session_id)
    return ServerHello(version,random,len(session_id),session_id, cipher_suite,len(compression_method),compression_method).to_bytes()

def server_key_exchange():
    print("Send server key exchange msg")
    dh_p = 23
    dh_g = 5
    dh_Xs = 15
    dh_Ys = pow(dh_g, dh_Xs, dh_p) 
    params = ServerDHParams(dh_p.to_bytes(),dh_g.to_bytes(),dh_Ys.to_bytes())
    md5_hash = hashlib.md5(connection.client_random+connection.server_random+params.to_bytes()).digest()
    signature = Signature(md5_hash)
    return ServerKeyExchange(params,signature).to_bytes()

def server_hello_done():
    print('Send server hello done')
    return b''
def server_response():
    fragment = Handshake(2,server_hello()).to_bytes()
    print('fragment leng: ', len(fragment))
    data = SSLPlaintext(22,version,len(fragment),fragment).to_bytes()
    return data

    

while True:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST,PORT))
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            while True:
                data = conn.recv(1024)
                if not data: break
                # print(data)
                # print(len(data))
                get_data(data)
                # data2 = sendHello()
                # conn.sendall(server_response())
                
                fragment = Handshake(12,server_key_exchange()).to_bytes()
                print('server key exchange fragment leng: ', len(fragment))
                print('server key exchange fragment: ',fragment)
                ssl_server_key_exchange = SSLPlaintext(22,version,len(fragment),fragment).to_bytes()
                # conn.sendall(ssl_server_key_exchange)
                
                
                fragment = Handshake(14,server_hello_done()).to_bytes()
                print('server hello done fragment leng: ', len(fragment))
                print('server hello done fragment: ',fragment)
                ssl_server_hello_done = SSLPlaintext(22,version,len(fragment),fragment).to_bytes()
                conn.sendall(server_response()+ssl_server_key_exchange+ssl_server_hello_done)
                break

            
