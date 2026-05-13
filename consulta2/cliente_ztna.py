import socket, json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

def solicitar_recurso(archivo_deseado):
    with open("sanitario.crt", "r") as f: cert_data = f.read()
    with open("sanitario.key", "rb") as f: 
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 65432))

    nonce = client.recv(32)
    signature = private_key.sign(nonce, ec.ECDSA(hashes.SHA256()))
    
    payload = {
        "certificate": cert_data,
        "signature": signature.hex(),
        "request_resource": archivo_deseado,
        "context": {
            "location": "Hospital_Sevilla_LAN",
            "tpm": True,
            "disk": "encrypted"
        }
    }
    
    client.sendall(json.dumps(payload).encode())
    respuesta = json.loads(client.recv(4096).decode())
    
    print(f"\n--- Petición de: {archivo_deseado} ---")
    if respuesta['status'] == 'success':
        print(f"CONTENIDO RECIBIDO:\n{respuesta['data']}")
    else:
        print(f"ACCESO DENEGADO: {respuesta['message']}")
    client.close()

if __name__ == "__main__":
    # Prueba 1: Acceder a recurso permitido
    solicitar_recurso("historia_paciente_A.txt")
    # Prueba 2: Acceder a recurso NO permitido (Facturación)
    solicitar_recurso("facturacion.txt")