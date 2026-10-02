import os

from cryptography.hazmat.primitives import serialization

from module3_center_auth.pki_setup import (
    generate_ca,
    issue_center_cert,
    save_cert_bundle,
)


CERTS_DIR = "certs"


def main():
    os.makedirs(CERTS_DIR, exist_ok=True)

    # Generate one persistent ExamShield Root CA
    print("Generating ExamShield Root CA...")
    ca_key, ca_cert = generate_ca()

    # Save CA private key
    ca_key_path = os.path.join(
        CERTS_DIR,
        "examshield_ca.key.pem"
    )

    with open(ca_key_path, "wb") as file:
        file.write(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save CA certificate
    ca_cert_path = os.path.join(
        CERTS_DIR,
        "examshield_ca.cert.pem"
    )

    with open(ca_cert_path, "wb") as file:
        file.write(
            ca_cert.public_bytes(serialization.Encoding.PEM)
        )

    print("✓ Root CA created")

    # Create center_001 using this CA
    center_id = "center_001"

    center_key, center_cert = issue_center_cert(
        center_id,
        ca_key,
        ca_cert,
    )

    save_cert_bundle(
        center_id,
        center_key,
        center_cert,
        CERTS_DIR,
    )

    print(f"✓ {center_id} certificate created")

    print("\nCertificate setup completed.")
    print("You can now register additional centers from the Flask UI.")


if __name__ == "__main__":
    main()