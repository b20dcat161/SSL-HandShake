import os
import hashlib
from dataclasses import dataclass, field
from enum import _simple_enum

# A.1 Record Layer
    # struct {
    #         uint8 major, minor;
    #     } ProtocolVersion;
@dataclass
class ProtocolVersion:
    major: int
    minor: int
    def to_bytes(self):
        return self.major.to_bytes()+ self.minor.to_bytes()
        # return self.major.encode()+self.minor.encode()

    #   enum {
    #         change_cipher_spec(20), alert(21), handshake(22),
    #         application_data(23), (255)
    #     } ContentType;
@dataclass
class SSLPlaintext :
    type: int
    version: ProtocolVersion
    length: int
    fragment: bytes
    def to_bytes(self):
        return self.type.to_bytes()+self.version.to_bytes()+self.length.to_bytes(2)+self.fragment

def fragment(type,version,message):
    return  SSLPlaintext(1,version,len(message),message).to_bytes()

         
# 1.2 record Compression and Decompression (options) : N/A
        # struct {
        #     ContentType type;       /* same as SSLPlaintext.type */
        #     ProtocolVersion version;/* same as SSLPlaintext.version */
        #     uint16 length;
        #     opaque fragment[SSLCompressed.length];
        # } SSLCompressed;
    
# 1.3  Record Payload Protection and the CipherSpec
        # struct {
        #     ContentType type;
        #     ProtocolVersion version;
        #     uint16 length;
        #     select (CipherSpec.cipher_type) {
        #         case stream: GenericStreamCipher;
        #         case block: GenericBlockCipher;
        #     } fragment;
        # } SSLCiphertext;
        
# 1.3.1 Null or Standard Stream Cipher
#  stream-ciphered struct {
#             opaque content[SSLCompressed.length];
#             opaque MAC[CipherSpec.hash_size];
#         } GenericStreamCipher;
#  hash(MAC_write_secret + pad_2 +
#              hash(MAC_write_secret + pad_1 + seq_num +
#                   SSLCompressed.type + SSLCompressed.length +
#                   SSLCompressed.fragment));

#   block-ciphered struct {
#             opaque content[SSLCompressed.length];
#             opaque MAC[CipherSpec.hash_size];
#             uint8 padding[GenericBlockCipher.padding_length];
#             uint8 padding_length;
#         } GenericBlockCipher;

# 2. Change Cipher Spec Protocol
#    struct {
#             enum { change_cipher_spec(1), (255) } type;
#         } ChangeCipherSpec;

@dataclass
class ChangeCipherSpec:
    type: int
    def to_bytes(self):
        return self.type.to_bytes()
    
#3 Alert Protocol
#    enum { warning(1), fatal(2), (255) } AlertLevel;

#         enum {
#             close_notify(0),
#             unexpected_message(10),
#             bad_record_mac(20),
#             decompression_failure(30),
#             handshake_failure(40),
#             no_certificate(41),
#             bad_certificate(42),
#             unsupported_certificate(43),
#             certificate_revoked(44),
#             certificate_expired(45),
#             certificate_unknown(46),
#             illegal_parameter (47)
#             (255)
#         } AlertDescription;

#         struct {
#             AlertLevel level;
#             AlertDescription description;
#         } Alert;


# A.4 Handshake protocol
#    enum {
#             hello_request(0), client_hello(1), server_hello(2),
#             certificate(11), server_key_exchange (12),
#             certificate_request(13), server_hello_done(14),
#             certificate_verify(15), client_key_exchange(16),
#             finished(20), (255)
#         } HandshakeType;


#         struct {
#             HandshakeType msg_type;    /* handshake type */
#             uint24 length;             /* bytes in message */
#             select (HandshakeType) {
#                 case hello_request: HelloRequest;
#                 case client_hello: ClientHello;
#                 case server_hello: ServerHello;
#                 case certificate: Certificate;
#                 case server_key_exchange: ServerKeyExchange;
#                 case certificate_request: CertificateRequest;
#                 case server_hello_done: ServerHelloDone;
#                 case certificate_verify: CertificateVerify;
#                 case client_key_exchange: ClientKeyExchange;
#                 case finished: Finished;
#             } body;
#         } Handshake;
@dataclass
class Handshake:
    msg_type: int
    body: bytes
    length: int = field(init=False)
    # body: bytes = field(init=False)
    def __post_init__(self):
        # if self.msg_type == 0: self.body = HelloRequest().to_bytes()
        # elif self.msg_type == 1: self.body =  ClientHello().to_bytes()
        # elif self.msg_type == 2: self.body =  ServerHello().to_bytes()
        # elif self.msg_type == 12: self.body =  ServerKeyExchange().to_bytes()
        # elif self.msg_type == 14: self.body =  ServerHelloDone().to_bytes()
        # elif self.msg_type == 16: self.body =  ClientKeyExchange().to_bytes()
        # elif self.msg_type == 20: self.body =  Finished().to_bytes()
        # else: self.body = b''
        self.length = len(self.body)
    def to_bytes(self):
        return self.msg_type.to_bytes()+self.length.to_bytes(3)+self.body
        
# 5.1.1 hello request
#    struct { } HelloRequest;
class HelloRequest:
    def to_bytes(self):
        return b''

# 5.1.2 client hello
#      struct {
#           uint32 gmt_unix_time;
#           opaque random_bytes[28];
#       } Random;
@dataclass
class Random:
    gmt_unix_time: int = 9999
    random_bytes: bytes = os.urandom(28)
    def to_bytes(self):
        return self.gmt_unix_time.to_bytes(4,'big')+self.random_bytes
    
    # @classmethod
    # def generate(cls):
        
    #     return random_bytes




#session
#     opaque SessionID<0..32>; (độ dài 0-32, null nếu phiên mới, nội dung do server đặt)
#     uint8 CipherSuite[2];
#     enum { null(0), (255) } CompressionMethod;
#          struct {
#             ProtocolVersion client_version;
#             Random random;
#             SessionID session_id;
#             CipherSuite cipher_suites<2..2^16-1>;
#             CompressionMethod compression_methods<1..2^8-1>;
#         } ClientHello;
@dataclass
class ClientHello:
    server_version: ProtocolVersion
    random : Random
    session_id_length: int
    session_id: bytes
    cipher_suite_length: int
    cipher_suite: bytes
    compression_method_length: int
    compression_method: bytes
    @classmethod
    def encode(self):
        return self.server_version.encode()
    def to_bytes(self):
        return self.server_version.to_bytes() + self.random.to_bytes() +self.session_id_length.to_bytes(1)+\
            self.session_id+self.cipher_suite_length.to_bytes(2)+self.cipher_suite+self.compression_method_length.to_bytes(1)+self.compression_method

#    struct {
#             ProtocolVersion server_version;
#             Random random;
#             SessionID session_id;
#             CipherSuite cipher_suite;
#             CompressionMethod compression_method;
#         } ServerHello;
@dataclass
class ServerHello:
    server_version: ProtocolVersion
    random: Random
    session_id_length: int
    session_id: bytes
    cipher_suite: bytes
    compression_method_length: int
    compression_method: bytes
    def to_bytes(self):
        return self.server_version.to_bytes()+self.random.to_bytes()+self.session_id_length.to_bytes()+\
            self.session_id+self.cipher_suite+self.compression_method_length.to_bytes()+self.compression_method
    
    
# Server Certificate
#         opaque ASN.1Cert<1..2^24-1>;
#         struct {
#             ASN.1Cert certificate_list<1..2^24-1>;
#         } Certificate;
        
# Server Key Exchange Message

#         enum { rsa, diffie_hellman, fortezza_kea }
#                KeyExchangeAlgorithm;

#         struct {
#             opaque rsa_modulus<1..2^16-1>;
#             opaque rsa_exponent<1..2^16-1>;
#         } ServerRSAParams;
        
#         struct {
#             opaque dh_p<1..2^16-1>;
#             opaque dh_g<1..2^16-1>;
#             opaque dh_Ys<1..2^16-1>;
#         } ServerDHParams;     /* Ephemeral DH parameters */
@dataclass
class ServerDHParams:
    dh_p: bytes
    dh_g: bytes
    dh_Ys: bytes
    dh_p_length: int = field(init=False)
    dh_g_length: int = field(init=False)
    dh_Ys_length: int = field(init=False)
    def __post_init__(self):
        self.dh_p_length = len(self.dh_p)
        self.dh_g_length = len(self.dh_g)
        self.dh_Ys_length = len(self.dh_Ys)
    def to_bytes(self):
        return self.dh_p_length.to_bytes(2)+self.dh_p+self.dh_g_length.to_bytes(2)+self.dh_g+self.dh_Ys_length.to_bytes(2)+self.dh_Ys
    
#            struct {
#             opaque r_s [128];
#         } ServerFortezzaParams;

#        struct {
#             select (KeyExchangeAlgorithm) {
#                 case diffie_hellman:
#                     ServerDHParams params;
#                     Signature signed_params;
#                 case rsa:
#                     ServerRSAParams params;
#                     Signature signed_params;
#                 case fortezza_kea:
#                     ServerFortezzaParams params;
#             };
#         } ServerKeyExchange;
@dataclass
class Signature:
    md5_hash: bytes
    def to_bytes(self):
        return self.md5_hash
    
# md5_hash:  MD5(ClientHello.random + ServerHello.random +
#       ServerParams);

@dataclass
class ServerKeyExchange:
    params: ServerDHParams
    signed_params: Signature
    def to_bytes(self):
        return self.params.to_bytes()+self.signed_params.to_bytes()
#             enum { anonymous, rsa, dsa } SignatureAlgorithm;

#         digitally-signed struct {
#             select(SignatureAlgorithm) {
#                 case anonymous: struct { };
#                 case rsa:
#                     opaque md5_hash[16];
#                     opaque sha_hash[20];
#                 case dsa:
#                     opaque sha_hash[20];
#             };
#         } Signature;

        
# Certificate Request
#   enum {
#             rsa_sign(1), dss_sign(2), rsa_fixed_dh(3), dss_fixed_dh(4),
#             rsa_ephemeral_dh(5), dss_ephemeral_dh(6), fortezza_kea(20),
#             (255)
#         } ClientCertificateType;

#         opaque DistinguishedName<1..2^16-1>;

#         struct {
#             ClientCertificateType certificate_types<1..2^8-1>;
#             DistinguishedName certificate_authorities<3..2^16-1>;
#         } CertificateRequest;

@dataclass
class ServerHelloDone:
    def to_bytes(self):
        return b''

#  Server Hello Done
#   struct { } ServerHelloDone;
  
#    Client Certificate

# Client Key Exchange Message
#     struct {
#             select (KeyExchangeAlgorithm) {
#                 case rsa: EncryptedPreMasterSecret;
#                 case diffie_hellman: ClientDiffieHellmanPublic;
#                 case fortezza_kea: FortezzaKeys;
#             } exchange_keys;
#         } ClientKeyExchange;
@dataclass 
class ClientDiffieHellmanPublic:
    dh_public: int
    def to_bytes(self):
        return self.dh_public.to_bytes()
@dataclass 
class ClientKeyExchange:
    exchange_keys: ClientDiffieHellmanPublic
    length: int = None
    def __post_init__(self):
        self.length = len(self.exchange_keys.to_bytes())
    def to_bytes(self):
        return self.length.to_bytes(2)+self.exchange_keys.to_bytes()
# RSA Encrypted Premaster Secret Message
#       struct {
#             ProtocolVersion client_version;
#             opaque random[46];
#         } PreMasterSecret;

#         struct {
#             public-key-encrypted PreMasterSecret pre_master_secret;
#         } EncryptedPreMasterSecret;
        
# FORTEZZA Key Exchange Message
#   struct {
#             opaque y_c<0..128>;
#             opaque r_c[128];
#             opaque y_signature[40];
#             opaque wrapped_client_write_key[12];
#             opaque wrapped_server_write_key[12];
#             opaque client_write_iv[24];
#             opaque server_write_iv[24];
#             opaque master_secret_iv[24];
#             block-ciphered opaque encrypted_pre_master_secret[48];
#         } FortezzaKeys;

#   Client Diffie-Hellman Public Value
#     enum { implicit, explicit } PublicValueEncoding;
#         struct {
#             select (PublicValueEncoding) {
#                 case implicit: struct { };
#                 case explicit: opaque dh_Yc<1..2^16-1>;
#             } dh_public;
#         } ClientDiffieHellmanPublic;
        

#  Certificate Verify

#           struct {
#                Signature signature;
#           } CertificateVerify;

#         CertificateVerify.signature.md5_hash
#                    MD5(master_secret + pad_2 +
#                        MD5(handshake_messages + master_secret + pad_1));
#         Certificate.signature.sha_hash
#                    SHA(master_secret + pad_2 +
#                        SHA(handshake_messages + master_secret + pad_1));
                   
# Finished
#      enum { client(0x434C4E54), server(0x53525652) } Sender;

#         struct {
#             opaque md5_hash[16];
#             opaque sha_hash[20];
#         } Finished;
# master_secret =
#           MD5(pre_master_secret + SHA('A' + pre_master_secret +
#               ClientHello.random + ServerHello.random)) +
#           MD5(pre_master_secret + SHA('BB' + pre_master_secret +
#               ClientHello.random + ServerHello.random)) +
#           MD5(pre_master_secret + SHA('CCC' + pre_master_secret +
#               ClientHello.random + ServerHello.random));
def calc_master_secret(pre_master_secret: int, client_random, server_random):
    def sha1(data):
        return hashlib.sha1(data).digest()
    def md5(data):
        return hashlib.md5(data).digest()
    return b''.join(
        md5(pre_master_secret.to_bytes()+sha1(label + pre_master_secret.to_bytes() +client_random +server_random))
        for label in (b'A', b'BB',b'CCC')
    )
    
    
@dataclass
class Finished:
    md5_hash: bytes
    def to_bytes(self):
        return self.md5_hash

def calc_md5_hash(data):
    return hashlib.md5(data).digest()
#        md5_hash:  MD5(master_secret + pad2 + MD5(handshake_messages + Sender
#       + master_secret + pad1));

#    sha_hash:  SHA(master_secret + pad2 + SHA(handshake_messages + Sender
#       + master_secret + pad1));

# A.6.  The CipherSuite
#  CipherSuite SSL_NULL_WITH_NULL_NULL                = { 0x00,0x00 };
#  CipherSuite SSL_RSA_WITH_NULL_MD5                  = { 0x00,0x01 };
#      CipherSuite SSL_RSA_WITH_NULL_SHA                  = { 0x00,0x02 };
#      CipherSuite SSL_RSA_EXPORT_WITH_RC4_40_MD5         = { 0x00,0x03 };
#      CipherSuite SSL_RSA_WITH_RC4_128_MD5               = { 0x00,0x04 };
#      CipherSuite SSL_RSA_WITH_RC4_128_SHA               = { 0x00,0x05 };
#      CipherSuite SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5     = { 0x00,0x06 };
#      CipherSuite SSL_RSA_WITH_IDEA_CBC_SHA              = { 0x00,0x07 };
#      CipherSuite SSL_RSA_EXPORT_WITH_DES40_CBC_SHA      = { 0x00,0x08 };
#      CipherSuite SSL_RSA_WITH_DES_CBC_SHA               = { 0x00,0x09 };
#      CipherSuite SSL_RSA_WITH_3DES_EDE_CBC_SHA          = { 0x00,0x0A };

# A.7.  The CipherSpec 
#        enum { stream, block } CipherType;

#         enum { true, false } IsExportable;

#         enum { null, rc4, rc2, des, 3des, des40, fortezza }
#             BulkCipherAlgorithm;

#         enum { null, md5, sha } MACAlgorithm;

#         struct {
#             BulkCipherAlgorithm bulk_cipher_algorithm;
#             MACAlgorithm mac_algorithm;
#             CipherType cipher_type;
#             IsExportable is_exportable
#             uint8 hash_size;
#             uint8 key_material;
#             uint8 IV_size;
#         } CipherSpec;

@dataclass
class SSLSession:
    session_id: bytes
    compression_method: bytes
    cipher_spec: bytes
    master_secret: bytes
    is_resumable: bytes
    
@dataclass
class SSLConnection:
    server_random: bytes = None
    client_random: bytes = None
    server_write_mac_secret: bytes =None
    client_write_mac_secret: bytes = None
    server_write_key: bytes = None
    client_write_key: bytes = None
    sequence_numbers: bytes = None
    
     
    
