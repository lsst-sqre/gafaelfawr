kubectl create secret generic jwt-authorizer-config --from-file=./authorizer.cfg --namespace=lsst-pdac
# docker run -ti --rm python:3-alpine python -c 'import secrets,base64; print(base64.b64encode(base64.b64encode(secrets.token_bytes(16))));'
kubectl create secret generic lsst-lsp-int-oauth2 --from-literal=client_secret=... --from-literal=cookie_secret=... --namespace=lsst-pdac
