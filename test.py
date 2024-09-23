# from module import *

# bin1 = Random.gmt_unix_time
# bin2 = Random()
# print(bin1)
# str = '1234'
# str_encoded = str.encode()
# # data2 = bin1 +str_encoded
# # print(data2)
# # print(len(data2))
# print(bin2.gmt_unix_time)
# hex_value = 0x434C4E54
# print(hex_value)  # 1129337556 (in dưới dạng số thập phân)
# CLIENT_SENDER = bytes.fromhex('434C4E54')  # "CLNT"
# SERVER_SENDER = bytes.fromhex('53525652')  # "SRVR"
# print(CLIENT_SENDER)
import hashlib

# Các giá trị giả định
master_secret = b'my_secret_key'  # Giá trị master_secret được chia sẻ giữa client và server
handshake_messages = b'handshake_messages_data'  # Chuỗi handshake trước đó

# Các padding (giá trị đệm)
pad1 = b'\x36' * 48  # Padding 1 cho cả MD5 và SHA
pad2 = b'\x5c' * 48  # Padding 2 cho cả MD5 và SHA

# Sender (Client hoặc Server)
CLIENT_SENDER = bytes.fromhex('434C4E54')  # "CLNT"
SERVER_SENDER = bytes.fromhex('53525652')  # "SRVR"

# Hàm tính toán MD5 hash
def calculate_md5_hash(sender):
    inner_md5 = hashlib.md5(master_secret + pad1 + handshake_messages + sender).digest()
    final_md5_hash = hashlib.md5(master_secret + pad2 + inner_md5).digest()
    return final_md5_hash

# Hàm tính toán SHA-1 hash
def calculate_sha_hash(sender):
    inner_sha = hashlib.sha1(master_secret + pad1 + handshake_messages + sender).digest()
    final_sha_hash = hashlib.sha1(master_secret + pad2 + inner_sha).digest()
    return final_sha_hash

# Tính toán cho Client
client_md5_hash = calculate_md5_hash(CLIENT_SENDER)
client_sha_hash = calculate_sha_hash(CLIENT_SENDER)

# Tính toán cho Server
server_md5_hash = calculate_md5_hash(SERVER_SENDER)
server_sha_hash = calculate_sha_hash(SERVER_SENDER)

# Hiển thị kết quả
print("Client MD5 Hash:", client_md5_hash.hex())
print("Client SHA Hash:", client_sha_hash.hex())

print("Server MD5 Hash:", server_md5_hash.hex())
print("Server SHA Hash:", server_sha_hash.hex())


string = b''
if not string:
    print("none")
    
num = 36
num = num.to_bytes(2)

str1 = b'\x00/'
str2 = b'\x00\x02'

if str1 == str2:
    print('y')
    
import hashlib

# Data in bytes
data = b"your data here"

# Compute MD5 hash
md5_hash = hashlib.md5(data).digest()

# Output the MD5 hash as bytes
print(md5_hash)
print(len(md5_hash))