from flask import Flask, render_template, request
from cipher.caesar import CaesarCipher

app = Flask(__name__, template_folder="templates")

# home page
@app.route('/')
def home():
    return render_template('index.html')

# caesar page
@app.route('/caesar')
def caesar():
    return render_template('caesar.html')

# encrypt
@app.route('/encrypt', methods=['POST'])
def caesar_encrypt():
    text = request.form['InputPlaintext']
    key = int(request.form['InputKeyNum'])

    Caesar = CaesarCipher()
    encrypted_text = Caesar.encrypt_text(text, key)

    return f"text: {text}<br>key: {key}<br>encrypted text: {encrypted_text}"

# decrypt
@app.route('/decrypt', methods=['POST'])
def caesar_decrypt():
    text = request.form['InputCiphertext']
    key = int(request.form['InputKeyCipher'])

    Caesar = CaesarCipher()
    decrypted_text = Caesar.decrypt_text(text, key)

    return f"text: {text}<br>key: {key}<br>decrypted text: {decrypted_text}"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050, debug=True)