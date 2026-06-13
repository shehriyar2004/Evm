#!/bin/bash

# Create folder for certificates
mkdir -p rsa_keys
mkdir -p tls_certs

echo "Generating RSA private key..."
openssl genpkey -algorithm RSA -out rsa_keys/private.pem -pkeyopt rsa_keygen_bits:2048

echo "Extracting RSA public key..."
openssl rsa -pubout -in rsa_keys/private.pem -out rsa_keys/public.pem

echo "Generating TLS private key..."
openssl genrsa -out tls_certs/server.key 2048

echo "Generating TLS certificate (self-signed)..."
openssl req -new -x509 -key tls_certs/server.key -out tls_certs/server.crt -days 365 \
    -subj "/C=PK/ST=Sindh/L=Karachi/O=University/OU=CN Department/CN=VotingServer"

echo "Certificate generation complete!"

