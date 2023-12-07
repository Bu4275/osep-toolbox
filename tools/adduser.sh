useradd rilak -s /bin/bash
usermod --password $(echo 'P@ssw0rd' | openssl passwd -1 -stdin) rilak
usermod -aG sudo rilak
echo "add user rilak / P@ssw0rd"