from app.crypto.pki import load_cert_from_file, verify_cert

ca = load_cert_from_file("certs/ca.crt.pem")
client = load_cert_from_file("certs/client.crt.pem")

ok, reason = verify_cert(client, ca, expected_cn="client.local")
print(ok, reason)
