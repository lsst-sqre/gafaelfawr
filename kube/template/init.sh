#!/bin/bash

echo "Hostname:"
read HOSTNAME

echo "Kubernetes Namespace:"
read NAMESPACE

echo "CILogon client ID for hostname (for callback https://$HOSTNAME/oauth2/callback):"
read OAUTH2_PROXY_CLIENT_ID

echo "CILogon Client Secret:"
read OAUTH2_PROXY_CLIENT_SECRET

OAUTH2_PROXY_COOKIE_SECRET=$(dd if=/dev/urandom bs=32 count=1 2> /dev/null | base64 -w0)

OAUTH2_PROXY_COOKIE_SECRET_B64=$(echo $OAUTH2_PROXY_COOKIE_SECRET | base64 -w0)
OAUTH2_PROXY_CLIENT_SECRET_B64=$(echo $OAUTH2_PROXY_CLIENT_SECRET | base64 -w0)

echo "Generating Issuer Keypair... private.pem, public.pem"
openssl genrsa -out private.pem 2048 2> /dev/null
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
modulus_hex=$(openssl rsa -pubin -inform PEM -modulus -noout -in public.pem | sed 's/Modulus=//')
modulus_urlsafe_b64=$(echo $modulus_hex | xxd -r -p | base64 -w0 | sed 's/+/-/g;s/\//_/g;s/=//g')

ISSUER_PRIVATE_KEY=$(cat private.pem)
ISSUER_PRIVATE_KEY_INDENT_10=$(echo "$ISSUER_PRIVATE_KEY" | sed 's/^/          /')
JWKS_N=$modulus_urlsafe_b64

AUTHORIZER_FLASK_SECRET=$(dd if=/dev/urandom bs=32 count=1 2> /dev/null | base64 -w0)

cat <<EOF > data.yml
AUTHORIZER_FLASK_SECRET: ${AUTHORIZER_FLASK_SECRET} 
HOSTNAME: ${HOSTNAME} 
ISSUER_PRIVATE_KEY_INDENT_10: |
$ISSUER_PRIVATE_KEY_INDENT_10
JWKS_N: ${JWKS_N} 
NAMESPACE: ${NAMESPACE} 
OAUTH2_PROXY_CLIENT_ID: ${OAUTH2_PROXY_CLIENT_ID} 
OAUTH2_PROXY_CLIENT_SECRET: ${OAUTH2_PROXY_CLIENT_SECRET} 
OAUTH2_PROXY_CLIENT_SECRET_B64: ${OAUTH2_PROXY_CLIENT_SECRET_B64} 
OAUTH2_PROXY_COOKIE_SECRET_B64: ${OAUTH2_PROXY_COOKIE_SECRET_B64} 
EOF

mustache="mustache"
mkdir -p $NAMESPACE
for f in $(find . -type f -name "*.yml")
do
    mkdir -p $(dirname ${NAMESPACE}/${f})
    $mustache data.yml ${f} > ${NAMESPACE}/${f}
done
