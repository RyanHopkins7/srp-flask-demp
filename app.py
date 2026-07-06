from flask import Flask, render_template, request, send_from_directory
import srp
import hashlib
import hmac

# Enable RFC5054 compatibility for interoperation with non pysrp SRP-6a implementations
srp.rfc5054_enable()

salt = None
verifier = None
svr = None
A_bytes = None
B_bytes = None

app = Flask(__name__)

@app.route('/', methods=['GET'])
def get_index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def post_register():
    global salt, verifier
    data = request.get_json()
    salt_hex = data.get('salt') 
    salt = bytes.fromhex(salt_hex)
    verifier_hex = data.get('verifier')
    verifier = bytes.fromhex(verifier_hex)
    return {'result': 'Registration request received.'}

@app.route('/start-authentication', methods=['POST'])
def post_start_authentication():
    global salt, verifier, svr, A_bytes, B_bytes
    data = request.get_json()
    A_hex = data.get('A')
    A_bytes = bytes.fromhex(A_hex)
    username = data.get('username')

    if salt is None or verifier is None:
        return {'error': 'User record not found. Please register first.'}, 400

    svr = srp.Verifier(username, salt, verifier, A_bytes, hash_alg=srp.SHA256, ng_type=srp.NG_4096)
    s, B_bytes = svr.get_challenge()

    if s is None or B_bytes is None:
        return {'error': 'Authentication failed.'}, 401

    return {
        's': s.hex(),
        'B': B_bytes.hex()
    }

@app.route('/verify-session', methods=['POST'])
def post_verify_session():
    global svr, A_bytes, B_bytes

    data = request.get_json()
    M_hex = data.get('M')
    M_bytes = bytes.fromhex(M_hex)

    # Force pysrp to populate K
    # Can't be used to interoperate with jsrp due to different implementations
    svr.verify_session(M_bytes)

    print(f"Server shared K: {svr.K.hex()}")
    
    expected_M = hashlib.sha256(A_bytes + B_bytes + svr.K).digest()
    
    if not hmac.compare_digest(expected_M, M_bytes):
        svr = None
        return {'error': 'Authentication failed.'}, 401

    HAMK = hashlib.sha256(A_bytes + expected_M + svr.K).digest()
    svr = None

    return {
        'result': 'Authentication successful.',
        'HAMK': HAMK.hex()
    }

@app.route('/static/<filename>', methods=['GET'])
def download_file(filename):
    return send_from_directory('static', filename)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
