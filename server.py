import socket
import hashlib
from module import *
from ssl_handler import *

HOST = ''
PORT = 1337
version = ProtocolVersion(3, 0) 
random = Random()
# print('r1',random)
session_id = b''
cipher_suite = b'\x00\x17'
compression_method = b''
ssl_session = SSLSession()
ssl_session.cipher_spec = CipherSpec()
# print('r2',random)
ssl_connection = SSLConnection()
ssl_connection.server_random = random.to_bytes()

dh_p = 23
dh_g = 5
dh_Xs = 15

handshake_messages = b'' # tất cả data từ các handshake messages (chỉ ở handshake layer)

def server_hello():
    print("send server hello - session id: ", session_id)
    return ServerHello(version, ssl_connection.server_random, len(session_id), session_id, cipher_suite, len(compression_method), compression_method).to_bytes()

def server_key_exchange():
    print("Send server key exchange msg")
    dh_Ys = pow(dh_g, dh_Xs, dh_p) 
    params = ServerDHParams(dh_p.to_bytes(), dh_g.to_bytes(), dh_Ys.to_bytes())
    md5_hash = hashlib.md5(ssl_connection.client_random + ssl_connection.server_random + params.to_bytes()).digest()
    signature = Signature(md5_hash)
    return ServerKeyExchange(params, signature).to_bytes()

def server_hello_done():
    print('Send server hello done')
    return b''

def handshake_response(msg_type):
    global handshake_messages
    body = b''
    if msg_type == 2:
        body = server_hello()
    elif msg_type == 12:
        body = server_key_exchange()
    elif msg_type == 14:
        body = server_hello_done()
    elif msg_type == 20:
        body = finished()
        
    fragment = Handshake(msg_type,body).to_bytes()
    handshake_messages += fragment
    print('fragment leng: ', len(fragment))
    data = SSLPlaintext(22, version, len(fragment), fragment).to_bytes()
    return data

while True:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(1)
        conn, addr = sock.accept()
        with conn:
            # print('Connected by', addr)
            # try:
            # recv = conn.recv(2048)
            # i =
            while True:
                # try:
                    data = recv_all(conn, 5)
                    # print(header)
                    # while True:/
                    # data = conn.recv(100)
                    if len(data) == 0: break
                    print('\r\nrecv',data)
                    header = data[:5]
                    # fragment = data[5:]
                    (content_type, server_version, length) = record_header_handler(header)
                    fragment = recv_all(conn, length)
                    if content_type == 22:
                        print('handshake msg', handshake_messages)
                        print('recv handshake msg')
                        msg_type = int.from_bytes(fragment[:1])
                        length = fragment[1:4]
                        print('msg type: ', msg_type)
                        body = fragment[4:]
                        if msg_type == 1:
                            handshake_messages += fragment
                            print('recv client hello')
                            protocol = body[:2]
                            print('protocol: ', protocol)
                            ssl_connection.client_random = body[2:34]
                            print('client random: ', ssl_connection.client_random)
                            session_id_length = int.from_bytes(body[34:35])
                            cipher_suite_index = 35 + session_id_length
                            session_id = body[35:cipher_suite_index]
                            print('session id: ', session_id)
                            cipher_suite_length = int.from_bytes(body[cipher_suite_index:cipher_suite_index+2])
                            compression_method_index = cipher_suite_index + 2 + cipher_suite_length
                            cipher_suite = body[cipher_suite_index+2:compression_method_index]
                            print('cipher suite: ', cipher_suite)
                            compression_method_length = int.from_bytes(body[compression_method_index:compression_method_index+1])
                            compression_method = body[compression_method_index+1:compression_method_index+1+compression_method_length]
                            print('compression_method: ', compression_method)
                            # Send ServerHello, ServerKeyExchange, ServerHelloDone
                            conn.sendall(handshake_response(2)+handshake_response(12)+handshake_response(14))
                            # ssl_server_key_exchange = SSLPlaintext(22, version, len(fragment), fragment).to_bytes()
                            # conn.sendall(server_key_exchange())
                            # conn.sendall(server_hello_done())
                        elif msg_type == 16:
                            handshake_messages += fragment
                            print('recv client key exchange')
                            dh_Yc_length = int.from_bytes(body[:2])
                            dh_Yc = int.from_bytes(body[2:2+dh_Yc_length])
                            print('dh_Yc: ',dh_Yc)
                            pre_master_secret = pow(dh_Yc,dh_Xs,dh_p)
                            print('calc pre master secret: ',pre_master_secret)
                            ssl_session.master_secret = calc_master_secret(pre_master_secret,ssl_connection.client_random,ssl_connection.server_random)
                            print('Calc master secret:', ssl_session.master_secret)
                        elif msg_type == 20:
                            print('recv finished')
                            print('send change cipher spec ...')
                            fragment = ChangeCipherSpec(1).to_bytes()
                            ssl_change_cipher_spec = SSLPlaintext(20,version,len(fragment),fragment).to_bytes()
                        
                            print('send finnish ...')
                            
                            md5_hash = calc_md5_hash(ssl_session.master_secret+b'\x5c'*48 +calc_md5_hash(handshake_messages+b'\x53\x52\x56\x52'+ssl_session.master_secret+b'\x36'*48))
                            sha_hash = calc_sha_hash(ssl_session.master_secret+b'\x5c'*48 +calc_sha_hash(handshake_messages+b'\x53\x52\x56\x52'+ssl_session.master_secret+b'\x36'*48))
                            fragment = Handshake(20,Finished(md5_hash,sha_hash).to_bytes()).to_bytes()
                            handshake_messages += fragment
                            ssl_finish = SSLPlaintext(22,version,len(fragment),fragment).to_bytes()
                            conn.sendall(ssl_change_cipher_spec+ssl_finish)
                            # conn.sendall(ssl_finish)
                            (ssl_connection.client_write_mac_secret,
                            ssl_connection.server_write_mac_secret,
                            ssl_connection.client_write_key,
                            ssl_connection.server_write_key) = gen_key(ssl_session.master_secret,ssl_connection.client_random,ssl_connection.server_random)
                            print(ssl_session)
                            print(ssl_connection)

                    elif content_type == 20:
                        print('recv change cipher spec')
                # except Exception as e:
                #     print(f"Error: {e}")
                #     break
