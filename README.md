code giao thức SSL 3.0 bằng python dựa trên mô tả của rfc, hiện hoàn thành:
- quá trình handshake, troa đổi khóa
- fix cứng cipher-suite và cipher spec, thuật toán trao đổi khóa: diffle hellman, hash: md5.

Cần code thêm:
* alert protocol
* SSLCompression
* SSLCipherTex

Tối ưu lại các hàm, thư viện.
