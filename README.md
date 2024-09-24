code giao thức SSL 3.0 bằng python dựa trên mô tả của rfc, hiện hoàn thành:
- quá trình handshake, troa đổi khóa
- fix cứng cipher-suite và cipher spec, thuật toán trao đổi khóa: diffle hellman, hash: md5.
![image](https://github.com/user-attachments/assets/8f4dd1b8-155a-4a5e-b049-a8f5eb228c39)

Cần code thêm:
* alert protocol
* SSLCompression
* SSLCipherTex

Tối ưu lại các hàm, thư viện.
