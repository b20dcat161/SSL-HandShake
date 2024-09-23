import socket 
import os
import hashlib
from module import *
from ssl_handler import *

HOST = 'localhost'
PORT = 1337
ssl_session = SSLSession(b'',b'',b'',b'',b'')
ssl_connection = SSLConnection()
SERVER = ('localhost',1337)
version = ProtocolVersion(3, 0) 
ssl_connection.client_random = Random().to_bytes()
session_id = b''
cipher_suite = b'\x00\x17'
cipher_spec = b''
compression_method = b''
dh_Yc = b''
dh_Xc = b''

handshake_messages = b'' # tất cả data từ các handshake messages (chỉ ở handshake layer)

def client_key_exchange():
    print('send client key exchange')
    dh_public = dh_Yc
    # fragment =
    # ssl_client_key_exchange = SSLPlaintext(22,ProtocolVersion(3,0),len(fragment),fragment).to_bytes()
    return ClientKeyExchange(ClientDiffieHellmanPublic(dh_public)).to_bytes()


        
def send_and_recv(sock:socket.socket,data:bytes) -> bytes:
    global ssl_session
    global ssl_connection
    global handshake_messages
    sock.sendall(data)
    # recv_data = b''
    states = 0
    data2= b''
    while True:
        try:
            header = recv_all(sock,5)
            (content_type, server_version, length) = record_header_handler(header)
            print('SSL version:', server_version,'Content type: ', content_type)
            fragment = recv_all(sock,length)
            if (content_type == 22):
                print('handshake msg', handshake_messages)
                print('')
                print('')
                print('recv Handshake msg')
                print('handshake fragment: ',fragment)
                (msg_type,length) = handshake_header_handler(fragment[:4])
                print('leng',length)
                print('msg_type',msg_type)
                body = fragment[4:4+length]
                print('body data:',body)
                if msg_type == 1:
                    print('recv client hello')
                elif msg_type ==2:
                    print('recv server hello')
                    handshake_messages += fragment
                    protocol = body[:2]
                    print('protocol: ',protocol)
                    
                    ssl_connection.server_random = body[2:34]
                    print('server random: ',ssl_connection.server_random)
                    
                    session_id_length = int.from_bytes(body[34:35])
                    cipher_suite_index =35 + session_id_length
                    session_id = body[35:cipher_suite_index]
                    print('session id: ',session_id)
                    
                    compression_method_index = cipher_suite_index+2
                    cipher_suite = body[cipher_suite_index:compression_method_index]
                    print('cipher suite: ',cipher_suite)
                    
                    compression_method_length = int.from_bytes(body[compression_method_index:compression_method_index+1])
                    ssl_session.compression_method=body[compression_method_index+1:compression_method_index+1+compression_method_length]
                    print('compression_method: ',ssl_session.compression_method)
                elif msg_type == 12:
                    print('recv server key exchane')
                    handshake_messages += fragment
                    (dh_p,dh_g,dh_Ys) = server_key_exchange_msg_handler(body)
                    global dh_Xc, dh_Yc
                    dh_Xc = 6 # a
                    dh_Yc = pow(dh_g, dh_Xc, dh_p) # A
                    print(f'p: {dh_p}, g: {dh_g}, Ys: {dh_Ys}')
                    print(f'dh_Yc = ',dh_Yc)
                    pre_master_secret= pow(dh_Ys,dh_Xc,dh_p)
                    print('pre_master_secret: ',pre_master_secret)
                    ssl_session.master_sercet = calc_master_secret(pre_master_secret,ssl_connection.client_random,ssl_connection.server_random)
                    print("Calc master secret: ", ssl_session.master_sercet)
                    # fragment =
                elif msg_type == 14:
                    print('recv server hello done')
                    handshake_messages += fragment
                    print('')
                    print('send client key exchange ...')
                    fragment = Handshake(16,client_key_exchange()).to_bytes()
                    handshake_messages += fragment
                    print('     client exchange fragment leng: ', len(fragment))
                    print('     client exchange fragment: ',fragment)
                    ssl_client_key_exchange = SSLPlaintext(22,version,len(fragment),fragment).to_bytes()
                    
                    print('send change cipher spec ...')
                    fragment = ChangeCipherSpec(1).to_bytes()
                    ssl_change_cipher_spec = SSLPlaintext(20,version,len(fragment),fragment).to_bytes()
                    
                    print('send finnish ...')
                    print('handshake msg', handshake_messages)
                    md5_hash = calc_md5_hash(ssl_session.master_secret+b'\x5c'*48 +calc_md5_hash(handshake_messages+b'\x43\x4C\x4e\x54'+ssl_session.master_secret+b'\x36'*48))
                    sha_hash = calc_sha_hash(ssl_session.master_secret+b'\x5c'*48 +calc_sha_hash(handshake_messages+b'\x43\x4C\x4e\x54'+ssl_session.master_secret+b'\x36'*48))
                    fragment = Handshake(20,Finished(md5_hash,sha_hash).to_bytes()).to_bytes()
                    ssl_finish = SSLPlaintext(22,version,len(fragment),fragment).to_bytes()
                    # sock.sendall(ssl_client_key_exchange)
                    # sock.sendall(ssl_change_cipher_spec)
                    # sock.sendall(ssl_finish)
                    sock.sendall(ssl_client_key_exchange+ssl_change_cipher_spec+ssl_finish)
                elif msg_type == 20:
                    print('recv finnished')
                else:
                    print('error type')
            elif content_type == 20:
                print('recv change cipher spec')
        except Exception as e:
            print(f'error {e}')
            break
        
    # return recv_data



def client_hello(ssl_session: SSLSession):
    print(ssl_session.cipher_spec)
    return ClientHello(version,Random(),len(ssl_session.session_id),ssl_session.session_id,len(cipher_suite),cipher_suite,len(ssl_session.compression_method),ssl_session.compression_method).to_bytes()

def handshake_protocol(sock,ssl_session: SSLSession):
    global handshake_messages
    fragment = Handshake(1,client_hello(ssl_session)).to_bytes()
    handshake_messages += fragment
    print('fragment leng: ', len(fragment))
    ssl_client_hello = SSLPlaintext(22,version,len(fragment),fragment).to_bytes()
    recv_data = send_and_recv(sock,ssl_client_hello)
    print('data recv: ',recv_data)
    # get_data(recv_data)
    
    
# def get_data(data):
#     global session_id
#     global cipher_suite
#     global compression_method
    
#     print('stegment: ',data)
#     content_type = int.from_bytes(data[:1])
#     if(content_type == 22):
#         print("recv handshake")
        
#     version = data[1:3]
#     print(int.from_bytes(version))
#     length=data[3:5]
#     print('data leng: ',int.from_bytes(length))
#     fragment = data[5:]
#     print(fragment)
#     if (content_type == 22):
#         msg_type = int.from_bytes(fragment[:1])
#         length =  fragment[1:4]
#         print('msg type: ', msg_type)
#         body = fragment[4:]
#         if msg_type == 2:
#             print('type: server hello')
#             protocol = body[:2]
#             print('protocol: ',protocol)
#             random = body[2:34]
#             print('server random: ',random)
#             session_id_length = int.from_bytes(body[34:35])
#             cipher_suite_index =35 + session_id_length
#             session_id = body[35:cipher_suite_index]
#             print('session id: ',session_id)
#             compression_method_index = cipher_suite_index+2
#             cipher_suite = body[cipher_suite_index:compression_method_index]
#             print('cipher suite: ',cipher_suite)
#             compression_method_length = int.from_bytes(body[compression_method_index:compression_method_index+1])
#             compression_method=body[compression_method_index+1:compression_method_index+1+compression_method_length]
#             print('compression_method: ',compression_method)



    

# while ssl_session.session_id:
#     application_messages = input('Client: ')
#     recv_data = send(SERVER,application_messages)
# handshake_protocol(ssl_session)


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(SERVER)
        handshake_protocol(sock, ssl_session)

main()