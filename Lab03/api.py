# rsa.py
import json
from flask import Flask, request, jsonify
from cipher.rsa import RSACipher
from cipher.ecc import ECCipher

app = Flask(__name__)

rsa_cipher = RSACipher()

@app.route('/api/rsa/generate_keys', methods=['GET'])
def rsa_generate_keys():
    rsa_cipher.generate_keys()
    return jsonify({"message": "Keys generated successfully"})

@app.route('/api/rsa/encrypt', methods=['POST'])
def rsa_encrypt():
    data = request.json
    # Kiểm tra dữ liệu đầu vào an toàn hơn
    if not data or 'message' not in data or 'key_type' not in data:
        return jsonify({"error": "Missing 'message' or 'key_type'"}), 400
        
    message = data['message']
    key_type = data['key_type']
    
    private_key, public_key = rsa_cipher.load_keys()
    
    if key_type == 'public':
        key = public_key
    elif key_type == 'private':
        key = private_key
    else:
        return jsonify({"error": "Invalid key type"}), 400
    
    # Gọi hàm mã hóa
    encrypted_bytes = rsa_cipher.encrypt(message, key)
    
    # --- SỬA LỖI Ở ĐÂY ---
    # Chuyển đổi bytes sang chuỗi hex để JSON có thể xử lý được
    if isinstance(encrypted_bytes, bytes):
        encrypted_message = encrypted_bytes.hex()
    else:
        # Trường hợp thư viện trả về sẵn string thì giữ nguyên
        encrypted_message = encrypted_bytes
        
    return jsonify({"encrypted_message": encrypted_message})

@app.route('/api/rsa/decrypt', methods=['POST'])
def rsa_decrypt():
    data = request.json
    ciphertext_hex = data['ciphertext']
    key_type = data['key_type']
    
    # Chuyển từ chuỗi hex về bytes
    try:
        ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    except ValueError:
        return jsonify({"error": "Invalid hex format in ciphertext"}), 400

    private_key, public_key = rsa_cipher.load_keys()
    
    if key_type != 'private':
        return jsonify({"error": "Decryption requires private key"}), 400
        
    # Truyền ciphertext_bytes (đã đổi từ hex) vào hàm decrypt
    decrypted_bytes = rsa_cipher.decrypt(ciphertext_bytes, private_key)
    
    # Nếu kết quả giải mã là bytes, cần decode sang string utf-8
    if isinstance(decrypted_bytes, bytes):
        decrypted_message = decrypted_bytes.decode('utf-8')
    else:
        decrypted_message = decrypted_bytes
        
    return jsonify({"decrypted_message": decrypted_message})

@app.route('/api/rsa/sign', methods=['POST'])
def rsa_sign():
    # Kiểm tra dữ liệu đầu vào an toàn
    data = request.json
    if not data or 'message' not in data:
        return jsonify({"error": "Missing 'message'"}), 400
        
    message = data['message']
    
    try:
        private_key, public_key = rsa_cipher.load_keys()
        if not private_key:
            return jsonify({"error": "Private key not found"}), 404
            
        # Gọi hàm ký
        signature_bytes = rsa_cipher.sign(message, private_key)
        
        # --- SỬA LỖI Ở ĐÂY ---
        # Chuyển bytes sang chuỗi hex để JSON hóa được
        if isinstance(signature_bytes, bytes):
            signature_hex = signature_bytes.hex()
        else:
            signature_hex = signature_bytes
            
        return jsonify({"signature": signature_hex})
        
    except Exception as e:
        return jsonify({"error": f"Signing failed: {str(e)}"}), 500

@app.route('/api/rsa/verify', methods=['POST'])
def rsa_verify_signature():
    # Kiểm tra dữ liệu đầu vào an toàn
    data = request.json
    if not data or 'message' not in data or 'signature' not in data:
        return jsonify({"error": "Missing 'message' or 'signature'"}), 400
        
    message = data['message']
    signature_hex = data['signature']
    
    try:
        private_key, public_key = rsa_cipher.load_keys()
        if not public_key:
            return jsonify({"error": "Public key not found"}), 404
            
        # --- SỬA LỖI Ở ĐÂY ---
        # Chuyển chuỗi hex từ client về bytes để thư viện xử lý
        try:
            signature_bytes = bytes.fromhex(signature_hex)
        except ValueError:
            return jsonify({"error": "Invalid signature format (expected hex string)"}), 400

        # Gọi hàm verify với dữ liệu đã chuyển đổi
        is_verified = rsa_cipher.verify(message, signature_bytes, public_key)
        
        return jsonify({"is_verified": is_verified})
        
    except Exception as e:
        return jsonify({"error": f"Verification failed: {str(e)}"}), 500
    # Thêm đoạn này trước hàm main
# ECC CIPHER ALGORITHM
ecc_cipher = ECCipher()

@app.route('/api/ecc/generate_keys', methods=['GET'])
def ecc_generate_keys():
    ecc_cipher.generate_keys()
    return jsonify({'message': 'Keys generated successfully'})

@app.route('/api/ecc/sign', methods=['POST'])
def ecc_sign_message():
    data = request.json
    message = data['message']
    private_key, _ = ecc_cipher.load_keys()
    signature = ecc_cipher.sign(message, private_key)
    signature_hex = signature.hex()
    return jsonify({'signature': signature_hex})

@app.route('/api/ecc/verify', methods=['POST'])
def ecc_verify_signature():
    data = request.json
    message = data['message']
    signature_hex = data['signature']

    _, public_key = ecc_cipher.load_keys()   # ✅ đúng key

    try:
        signature = bytes.fromhex(signature_hex)
        is_verified = ecc_cipher.verify(message, signature, public_key)
        return jsonify({'is_verified': is_verified})
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)