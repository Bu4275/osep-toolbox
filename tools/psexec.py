from pypsexec.client import Client
import sys

# Check https://github.com/jborean93/pypsexec
# creates an encrypted connection to the host with the username and password
c = Client("hostname", username="username", password="password")

# set encrypt=False for Windows 7, Server 2008
c = Client("hostname", username="username", password="password", encrypt=False)

# if Kerberos is available, this will use the default credentials in the
# credential cache
c = Client("hostname")

if len(sys.argv) != 5:
    print('Usage: python3 psexec.py <hostname> <username> <password>')
    print('Usage: python3 psexec.py 192.168.1.1 username@DOMAIN.LOCAL password')
    sys.exit(0)

hostname = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
command = sys.argv[4]

# you can also tell it to use a specific Kerberos principal in the cache
# without a password
c = Client(hostname, username=username, password=password)

c.connect()
try:
    c.create_service()

    # After creating the service, you can run multiple exe's without
    # reconnecting

    # run a simple cmd.exe program with arguments
    # stdout, stderr, rc = c.run_executable("cmd.exe",
    #                                       arguments="/c echo Hello World > C:\\users\\user\\desktop\\test.txt")
    
    # run a simple cmd.exe program with arguments
    stdout, stderr, rc = c.run_executable("cmd.exe",
                                          arguments="/c %s" % command)
finally:
    c.remove_service()
    c.disconnect()