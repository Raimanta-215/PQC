import subprocess
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

CA_CERT = "pqc_ca.crt"
CA_KEY = "pqc_ca.key"

@app.route('/ca/certificate', methods=['POST'])
def sign_csr():
    data = request.get_json()
    csr_content = data.get('csr')
    user_name = data.get('identity')

    if not csr_content:
        return jsonify({"error": "No CSR provided"}), 400

    temp_csr_path = f"temp_{user_name}.csr"
    temp_crt_path = f"temp_{user_name}.crt"

    with open(temp_csr_path, "w") as f:
        f.write(csr_content)

    try:
        command = [
                    "openssl", "x509", "-req",
                    "-in", temp_csr_path,
                    "-CA", CA_CERT,
                    "-CAkey", CA_KEY,
                    "-CAcreateserial",
                    "-out", temp_crt_path,
                    "-days", "365"

                ]
        ''' commands if using provider
        
                    "-provider-path", "/home/pki/oqs-provider/build/lib",
                    "-provider", "oqsprovider",
                    "-provider", "default"
        '''

        subprocess.run(command, check=True, capture_output=True, text=True)

        with open(temp_crt_path, "r") as f:
            crt_content = f.read()

        os.remove(temp_csr_path)
        os.remove(temp_crt_path)

        return jsonify({
            "status": "success",
            "certificate": crt_content
        })

    except subprocess.CalledProcessError as e:
        return jsonify({"error": "Erreur OpenSSL", "details": e.stderr}), 500


@app.route('/ca', methods=['GET'])
def send_root_cert():
    try:
        with open(CA_CERT, "r") as f:
            ca_cert_content = f.read()
        return jsonify({
            "status": "success",
            "certificate": ca_cert_content
        })
    except Exception as e:
        return jsonify({"error": "Failed to read CA certificate", "details": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)