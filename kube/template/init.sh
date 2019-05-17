#!/bin/bash

b64="base64 -w0"
uname | grep -i darwin > /dev/null
is_darwin_rc=$?

if [[ $is_darwin_rc -eq 0 ]]; then
    b64="base64"
fi

echo "Hostname:"
read HOSTNAME

echo "Kubernetes Namespace:"
read NAMESPACE

echo "CILogon client ID for hostname (for callback https://$HOSTNAME/oauth2/callback):"
read OAUTH2_PROXY_CLIENT_ID

echo "CILogon Client Secret:"
read OAUTH2_PROXY_CLIENT_SECRET

OAUTH2_PROXY_COOKIE_SECRET=$(dd if=/dev/urandom bs=32 count=1 2> /dev/null | $b64)

OAUTH2_PROXY_COOKIE_SECRET_B64=$(echo $OAUTH2_PROXY_COOKIE_SECRET | $b64)
OAUTH2_PROXY_CLIENT_SECRET_B64=$(echo $OAUTH2_PROXY_CLIENT_SECRET | $b64)

echo "Generating Issuer Keypair... private.pem, public.pem"
openssl genrsa -out private.pem 2048 2> /dev/null
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
modulus_hex=$(openssl rsa -pubin -inform PEM -modulus -noout -in public.pem | sed 's/Modulus=//')
modulus_urlsafe_b64=$(echo $modulus_hex | xxd -r -p | $b64 | sed 's/+/-/g;s/\//_/g;s/=//g')

ISSUER_PRIVATE_KEY=$(cat private.pem)
ISSUER_PRIVATE_KEY_INDENT_10=$(echo "$ISSUER_PRIVATE_KEY" | sed 's/^/          /')
JWKS_N=$modulus_urlsafe_b64

AUTHORIZER_FLASK_SECRET=$(dd if=/dev/urandom bs=32 count=1 2> /dev/null | $b64)


mkdir -p ${NAMESPACE}
mv *.pem ${NAMESPACE}

cat <<EOF > ${NAMESPACE}/data.yml
AUTHORIZER_FLASK_SECRET: ${AUTHORIZER_FLASK_SECRET} 
HOSTNAME: ${HOSTNAME} 
ISSUER_PRIVATE_KEY_INDENT_10: |2
$(echo "$ISSUER_PRIVATE_KEY_INDENT_10" | sed 's/^/  /')
JWKS_N: ${JWKS_N} 
NAMESPACE: ${NAMESPACE} 
OAUTH2_PROXY_CLIENT_ID: ${OAUTH2_PROXY_CLIENT_ID} 
OAUTH2_PROXY_CLIENT_SECRET: ${OAUTH2_PROXY_CLIENT_SECRET} 
OAUTH2_PROXY_CLIENT_SECRET_B64: ${OAUTH2_PROXY_CLIENT_SECRET_B64} 
OAUTH2_PROXY_COOKIE_SECRET_B64: ${OAUTH2_PROXY_COOKIE_SECRET_B64} 
EOF

j2="j2"

j2 --version > /dev/null
has_j2_rc=$?

if [[ $has_j2_rc -ne 0 ]]; then
    volumes=$(for dir in configmap deployment ing secret svc ${NAMESPACE}; do echo "-v `pwd`/$dir:/$dir"; done)
    j2="docker run $volumes -w / danielpanzella/j2cli"
fi

if [[ -n ${J2_BIN} ]]; then
    j2=${J2_BIN}
fi

for dir in configmap deployment ing secret svc
do
    for f in $(find $dir -type f -name "*.yml")
    do
        mkdir -p $(dirname ${NAMESPACE}/${f})
        $j2 ${f} ${NAMESPACE}/data.yml > ${NAMESPACE}/${f}
    done
done

echo "NOTICE: yaml and secrets created in the clear in $NAMESPACE."
