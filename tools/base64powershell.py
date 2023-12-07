import sys
import base64

class MyEncoder:
    @staticmethod
    def powershell_base64encode(s):
        return base64.b64encode(s.encode('utf16')[2:]).decode()

print(MyEncoder.powershell_base64encode(sys.argv[1]))
