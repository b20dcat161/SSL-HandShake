import random

# Bước 1: Cài đặt các tham số Diffie-Hellman
dh_p = 23  # Modulus (prime number)
dh_g = 5   # Generator (primitive root modulo p)

# Bước 2: Server tạo khóa riêng và tính khóa công khai
X_s = random.randint(2, dh_p - 2)  # Server's private key
Y_s = pow(dh_g, X_s, dh_p)         # Server's public key (Y_s = g^X_s mod p)
print("Server's private key (X_s):", X_s)
print("Server's public key (Y_s):", Y_s)

# Bước 3: Client tạo khóa riêng và tính khóa công khai
X_c = random.randint(2, dh_p - 2)  # Client's private key
Y_c = pow(dh_g, X_c, dh_p)         # Client's public key (Y_c = g^X_c mod p)
print("Client's private key (X_c):", X_c)
print("Client's public key (Y_c):", Y_c)

# Bước 4: Trao đổi khóa công khai giữa Client và Server

# Bước 5: Client tính toán pre-shared key bằng khóa công khai của server và khóa riêng của mình
pre_shared_key_client = pow(Y_s, X_c, dh_p)  # pre_shared_key_client = Y_s^X_c mod p
print("Pre-shared key calculated by Client:", pre_shared_key_client)

# Bước 6: Server tính toán pre-shared key bằng khóa công khai của client và khóa riêng của mình
pre_shared_key_server = pow(Y_c, X_s, dh_p)  # pre_shared_key_server = Y_c^X_s mod p
print("Pre-shared key calculated by Server:", pre_shared_key_server)

# Kiểm tra xem cả hai bên có cùng giá trị pre-shared key hay không
if pre_shared_key_client == pre_shared_key_server:
    print("Both Client and Server calculated the same pre-shared key!")
else:
    print("Error: Client and Server calculated different pre-shared keys!")
