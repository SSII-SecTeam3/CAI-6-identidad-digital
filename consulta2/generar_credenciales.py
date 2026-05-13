import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

def generar_pki():
    # 1. Generar la CA del Hospital (Raíz de confianza)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"CA Hospital Sevilla"),
    ])
    ca_cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.datetime.utcnow()).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(
        ca_key, hashes.SHA256())

    # 2. Generar Certificado para el Sanitario (Firmado por la CA)
    client_key = ec.generate_private_key(ec.SECP256R1())
    client_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Sanitario: Juan Perez"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Servicio de Salud"),
    ])
    client_cert = x509.CertificateBuilder().subject_name(client_subject).issuer_name(subject).public_key(
        client_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.datetime.utcnow()).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(ca_key, hashes.SHA256())

    # Guardar archivos
    with open("ca.crt", "wb") as f: f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    with open("sanitario.crt", "wb") as f: f.write(client_cert.public_bytes(serialization.Encoding.PEM))
    with open("sanitario.key", "wb") as f: f.write(client_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    print("Certificados ECC 256 bits generados correctamente.")

if __name__ == "__main__":
    generar_pki()