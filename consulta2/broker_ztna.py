import socket, json, os, datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

def verify_certificate(cert_bytes, ca_cert):
    try:
        client_cert = x509.load_pem_x509_certificate(cert_bytes)
        # 1. Vigencia
        now = datetime.datetime.utcnow()
        if now < client_cert.not_valid_before or now > client_cert.not_valid_after:
            return False, "Certificado caducado.", None, None
        
        # 2. Rol (Extraído del Common Name)
        subject = client_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        role = "personal_sanitario" if "Sanitario" in subject else "desconocido"

        # 3. Firma de la CA
        ca_cert.public_key().verify(
            client_cert.signature, client_cert.tbs_certificate_bytes,
            ec.ECDSA(client_cert.signature_hash_algorithm)
        )
        return True, "Certificado OK", client_cert.public_key(), role
    except Exception as e:
        return False, f"Error Certificado: {e}", None, None

def run_broker():
    with open("ca.crt", "rb") as f: ca_cert = x509.load_pem_x509_certificate(f.read())
    with open("policy.json", "r") as f: policy = json.load(f)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 65432))
    server.listen(1)
    print("[*] Broker ZTNA & Proxy activo en puerto 65432...")

    while True:
        conn, addr = server.accept()
        nonce = os.urandom(32)
        conn.sendall(nonce)
        
        try:
            data = conn.recv(8192)
            payload = json.loads(data.decode())
            
            # A. VALIDACIÓN DE IDENTIDAD (X.509 + Firma)
            cert_ok, msg, pub_key, role = verify_certificate(payload['certificate'].encode(), ca_cert)
            if not cert_ok:
                conn.sendall(json.dumps({"status": "error", "message": msg}).encode())
                continue
            
            pub_key.verify(bytes.fromhex(payload['signature']), nonce, ec.ECDSA(hashes.SHA256()))

            # B. VALIDACIÓN DE CONTEXTO (CBAC)
            ctx = payload['context']
            rules = policy['rules']
            hour = datetime.datetime.now().hour
            
            if ctx['location'] != rules['allowed_location'] or not (rules['working_hours']['start'] <= hour <= rules['working_hours']['end']):
                conn.sendall(json.dumps({"status": "denied", "message": "Contexto no autorizado (Ubicación/Hora)."}).encode())
                continue

            # C. LÓGICA DE REVERSE PROXY (Permisos por Recurso)
            req_resource = payload['request_resource']
            if req_resource in rules['permissions'].get(role, []):
                try:
                    with open(f"servidor_interno/{req_resource}", "r") as f:
                        response = {"status": "success", "data": f.read()}
                except:
                    response = {"status": "error", "message": "Archivo no encontrado en servidor."}
            else:
                response = {"status": "denied", "message": f"403 Forbidden: Su rol no tiene acceso a {req_resource}"}

            conn.sendall(json.dumps(response).encode())
        except Exception as e:
            print(f"Error procesando petición: {e}")
        finally:
            conn.close()

if __name__ == "__main__":
    run_broker()