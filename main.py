import argparse
import sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
import datetime


def generate_key(key_size):
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)

def generate_cert(name, issuer, issuer_key, public_key, not_valid_before, not_valid_after, is_ca=False):
    basic_contraints = x509.BasicConstraints(ca=is_ca, path_length=None)
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
               .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
               .public_key(public_key)
               .serial_number(x509.random_serial_number())
               .not_valid_before(not_valid_before)
               .not_valid_after(not_valid_after)
               .add_extension(basic_contraints, critical=True))
    cert = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())
    return cert

def generate_crl(issuer, issuer_key, revoked_certs):
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
    builder = builder.last_update(datetime.datetime.utcnow())
    builder = builder.next_update(datetime.datetime.utcnow() + datetime.timedelta(days=30))
    for cert in revoked_certs:
        builder = builder.add_revoked_certificate(cert)
    crl = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())
    return crl

def revoke_cert(cert, revocation_date):
    return x509.RevokedCertificateBuilder().serial_number(
        cert.serial_number
    ).revocation_date(
        revocation_date
    ).build(default_backend())


def load_cert(cert_path):
    with open(cert_path, 'rb') as f:
        cert_data = f.read()
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    return cert

def load_private_key(key_path):
    try:
        with open(key_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    except ValueError:
        print(f"Error: {key_path} does not contain a valid private key.")
        sys.exit(1)
    return private_key

def extend_cert_validity(cert, issuer_key, new_valid_to):
    builder = (x509.CertificateBuilder()
               .subject_name(cert.subject)
               .issuer_name(cert.issuer)
               .public_key(cert.public_key())
               .serial_number(cert.serial_number)
               .not_valid_before(cert.not_valid_before)
               .not_valid_after(new_valid_to)
               .add_extension(cert.extensions.get_extension_for_class(x509.BasicConstraints).value, critical=True))
    new_cert = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())
    return new_cert

def create_cert_with_new_signature(cert, new_issuer_key):
    builder = (x509.CertificateBuilder()
               .subject_name(cert.subject)
               .issuer_name(cert.issuer)
               .public_key(cert.public_key())
               .serial_number(cert.serial_number)
               .not_valid_before(cert.not_valid_before)
               .not_valid_after(cert.not_valid_after)
               .add_extension(cert.extensions.get_extension_for_class(x509.BasicConstraints).value, critical=True))
    new_cert = builder.sign(private_key=new_issuer_key, algorithm=hashes.SHA256())
    return new_cert

def save_private_key(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

def validate_cert(cert, issuer_cert):
    try:
        issuer_public_key = issuer_cert.public_key()
        issuer_public_key.verify(
            signature=cert.signature,
            data=cert.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


# Parse command-line arguments
parser = argparse.ArgumentParser(description='Generate a hierarchical chain of certificates')
parser.add_argument('--root-name', required=True, help='Common name for the root certificate')
parser.add_argument('--intermediate-name', required=True, help='Common name for the intermediate certificate')
parser.add_argument('--end-entity-name', required=True, help='Common name for the end-entity certificate')
parser.add_argument('--key-size', type=int, default=2048, help='Size of the RSA key to generate')
parser.add_argument('--validity', type=int, default=365, help='Number of days for the certificate to be valid')
args = parser.parse_args()
valid_from = datetime.datetime.utcnow()
valid_to = valid_from + datetime.timedelta(days=args.validity)

root_key = generate_key(args.key_size)
save_private_key(root_key, 'root_key.pem')
root_cert = generate_cert(args.root_name, args.root_name, root_key, root_key.public_key(), valid_from, valid_to, is_ca=True)

intermediate_key = generate_key(args.key_size)
save_private_key(intermediate_key, 'intermediate_key.pem')
intermediate_cert = generate_cert(args.intermediate_name, args.root_name, root_key, intermediate_key.public_key(), valid_from, valid_to, is_ca=True)

end_key = generate_key(args.key_size)
save_private_key(end_key, 'end_key.pem')
end_cert = generate_cert(args.end_entity_name, args.intermediate_name, intermediate_key, end_key.public_key(), valid_from, valid_to)


revocation_date = datetime.datetime.utcnow()
revoked_cert = revoke_cert(end_cert, revocation_date)

# CRL
crl = generate_crl(args.intermediate_name, intermediate_key, [revoked_cert])

with open(f'{args.root_name}.pem', 'wb') as f:
    f.write(root_cert.public_bytes(Encoding.PEM))
with open(f'{args.intermediate_name}.pem', 'wb') as f:
    f.write(intermediate_cert.public_bytes(Encoding.PEM))
with open(f'{args.end_entity_name}.pem', 'wb') as f:
    f.write(end_cert.public_bytes(Encoding.PEM))

with open('crl.pem', 'wb') as f:
    f.write(crl.public_bytes(Encoding.PEM))

#------------------------- extindere

existing_cert = load_cert(f'{args.end_entity_name}.pem')
existing_key = load_private_key('end_key.pem')
new_valid_to = existing_cert.not_valid_before + datetime.timedelta(days=365 * 2)  # 2 years
new_cert = extend_cert_validity(existing_cert, existing_key, new_valid_to)

with open('new_cert.pem', 'wb') as f:
    f.write(new_cert.public_bytes(Encoding.PEM))

existing_cert = load_cert('entity.pem')
new_key = generate_key(args.key_size)
new_cert = create_cert_with_new_signature(existing_cert, new_key)


with open('new_key.pem', 'wb') as f:
    f.write(new_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()))


end_cert = load_cert(f'{args.end_entity_name}.pem')
intermediate_cert = load_cert(f'{args.intermediate_name}.pem')

# Validare
valid = validate_cert(end_cert, intermediate_cert)

if valid:
    print("Certificate is valid.")
else:
    print("Certificate is not valid.")