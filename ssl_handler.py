from module import *
def record_header_handler(header: bytes):
    return (header[:1],header[1:3],int.from_bytes(header[3:])) #(content_type,version,fragment_length)

def handshake_header_handler(header: bytes):
    return (int.from_bytes(header[:1]),int.from_bytes(header[1:4])) #(msg_type,body_length)

def gen_key(dh_p,dh_g):
    import random
    
def server_key_exchange_msg_handler(body: bytes):
    dh_p_length = int.from_bytes(body[:2])
    dh_p = int.from_bytes(body[2:2+dh_p_length])
    dh_g_length = int.from_bytes(body[2+dh_p_length:4+dh_p_length])
    dh_g = int.from_bytes(body[4+dh_p_length:4+dh_p_length+dh_g_length])
    dh_Ys_length = int.from_bytes(body[4+dh_p_length+dh_g_length:6+dh_p_length+dh_g_length])
    dh_Ys = int.from_bytes(body[6+dh_p_length+dh_g_length:6+dh_p_length+dh_g_length+dh_Ys_length])
    return (dh_p,dh_g,dh_Ys)



def finished():
    print('send finished')
    fragment = Finished()