openssl req -new -x509 -nodes -out cert.crt -keyout priv.key -subj "/C=UK/ST=John/O=nasa"
cat priv.key cert.crt > nasa.pem
