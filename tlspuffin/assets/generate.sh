#!/bin/bash

set -e

params=(-subj "/CN=tlspuffin/C=SK")

# Certificates
openssl req -newkey rsa:2048 -nodes -keyout alice-key.pem -x509 -days 100000 -out alice.pem "${params[@]}"
openssl req -newkey rsa:2048 -nodes -keyout bob-key.pem -x509 -days 100000 -out bob.pem "${params[@]}"
openssl req -newkey rsa:2048 -nodes -keyout eve-key.pem -x509 -days 100000 -out eve.pem "${params[@]}"
openssl ecparam -out random-ec-key.pem -name secp256r1 -genkey
openssl req -new -key random-ec-key.pem -x509 -nodes -days 100000 -out random-ec.pem "${params[@]}"

echo "Convert keys to DER"
openssl rsa -inform pem -in alice-key.pem -outform der -out alice-key.der
openssl rsa -inform pem -in bob-key.pem -outform der -out bob-key.der
openssl rsa -inform pem -in eve-key.pem -outform der -out eve-key.der
openssl pkcs8 -topk8 -inform PEM -outform DER -in random-ec-key.pem -out random-ec-key.pkcs8.der -nocrypt

echo "Convert certs to DER"
openssl x509 -in bob.pem -out bob.der -outform DER
openssl x509 -in eve.pem -out eve.der -outform DER
openssl x509 -in alice.pem -out alice.der -outform DER
openssl x509 -in random-ec.pem -out random-ec.der -outform DER

openssl dgst -sha1 -sign eve-key.pem -out eve-signature
