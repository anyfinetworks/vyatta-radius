#!/bin/sh

# Create a private key for the CA. This only needs to be done if you
# want a new CA key.
[ ! -e ca-key.pem ] && openssl genrsa -out ca-key.pem 1024

# Create a self-signed certificate for the CA. This needs to be
# updated if it expires etc.
openssl req -config openssl.cnf -extensions ca_cert \
        -key ca-key.pem -new -x509 -days 3650 \
        -subj "/CN=Anyfi Networks Demo CA/emailAddress=info@anyfinetworks.com" \
        -out ca.pem

# Create a private key for the server. This only needs to be done if
# you want a new key.
[ ! -e server-key.pem ] && openssl genrsa -out server-key.pem 1024

# Create a certificate for the server. This needs to be updated if it
# expires etc.
openssl req -config openssl.cnf \
        -key server-key.pem -new \
        -subj "/CN=Anyfi Networks Demo/emailAddress=info@anyfinetworks.com" \
        -out server-csr.pem

# Sign the server certificate with the CA.
openssl ca -config openssl.cnf -extensions usr_cert \
        -days 3650 -notext -md sha256 \
        -in server-csr.pem \
        -out server.pem
