from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

def solicitar_datos_csr():
    print("\n--- Introduzca los datos para el Certificado del Servicio de Salud ---")
    print("(Pulse Enter para usar los valores por defecto entre corchetes)")
    
    pais = input("País [ES]: ") or "ES"
    estado = input("Comunidad autónoma [Andalucía]: ") or "Andalucía"
    localidad = input("Localidad [Sevilla]: ") or "Sevilla"
    organizacion = input("Organización [Servicio de Salud Público]: ") or "Servicio de Salud Público"
    unidad = input("Unidad Organizacional [Departamento médico]: ") or "Departamento Médico"
    nombre_comun = input("Nombre común (ej. Dr. Juan Pérez) [Dr. Empleado Ejemplo]: ") or "Dr. Empleado Ejemplo"
    email = input("Correo electrónico [empleado@salud.es]: ") or "empleado@salud.es"

    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, pais),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, estado),
        x509.NameAttribute(NameOID.LOCALITY_NAME, localidad),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organizacion),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, unidad),
        x509.NameAttribute(NameOID.COMMON_NAME, nombre_comun),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])

def generar_csr_ecc():
    print("\n[1/4] Iniciando generación de clave ECC de 256 bits...")
    # Generar clave privada ECC (curva SECP256R1, solicitada por los requisitos)
    clave_privada = ec.generate_private_key(ec.SECP256R1())

    # Obtener los datos dinámicamente por consola
    sujeto = solicitar_datos_csr()

    print("\n[2/4] Construyendo y firmando el Certificate Signing Request (CSR)...")
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        sujeto
    ).sign(clave_privada, hashes.SHA256())


    nombre_ficheros = sujeto.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    nombre_ficheros = nombre_ficheros.replace(" ", "_").replace(".", "").lower()
    print(f"[3/4] Guardando la clave privada ({nombre_ficheros}.key)...")
    
    
    with open(nombre_ficheros + ".key", "wb") as f_key:
        f_key.write(clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    print(f"[4/4] Guardando el CSR ({nombre_ficheros}.csr)...")
    with open(nombre_ficheros +".csr", "wb") as f_csr:
        f_csr.write(csr.public_bytes(serialization.Encoding.PEM))

    print("\nArchivos generados correctamente en el directorio actual.")

if __name__ == "__main__":
    generar_csr_ecc()