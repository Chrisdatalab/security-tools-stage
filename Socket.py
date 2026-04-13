import socket
from concurrent.futures import ThreadPoolExecutor
RULES = {
    "SSH": [b"SSH-"],

    "HTTP": [
        b"HTTP/", b"Server:", b"Content-Type", b"Set-Cookie",
        b"Location:", b"Date:"
    ],

    "TLS/HTTPS": [
        b"\x16\x03", b"\x15\x03", b"\x14\x03"
    ],

    "FTP": [
        b"FTP", b"220", b"FileZilla", b"vsFTPd"
    ],

    "SMTP": [
        b"SMTP", b"ESMTP", b"Postfix", b"Sendmail"
    ],

    "POP3": [
        b"+OK", b"POP3"
    ],

    "IMAP": [
        b"IMAP", b"* OK"
    ],

    "DNS": [
        b"\x00\x35", b"\x81\x80"
    ],

    "MySQL": [
        b"mysql", b"MariaDB", b"\x00\x00\x00\x0a"
    ],

    "PostgreSQL": [
        b"PostgreSQL", b"FATAL", b"invalid"
    ],

    "Redis": [
        b"+PONG", b"-ERR", b":1"
    ],

    "MongoDB": [
        b"MongoDB", b"errmsg"
    ],

    "Telnet": [
        b"\xff\xfb", b"\xff\xfd", b"\xff\xfc"
    ],

    "RDP": [
        b"\x03\x00\x00", b"Cookie: mstshash"
    ],

    "SMB": [
        b"\x00\x00\x00", b"SMB", b"\xffSMB"
    ],

    "LDAP": [
        b"\x30\x84", b"LDAP"
    ],

    "SNMP": [
        b"\x30\x2c", b"\x30\x29"
    ],

    "NTP": [
        b"\x1c", b"\x24"
    ],

    "VNC": [
        b"RFB"
    ],

    "Elasticsearch": [
        b"cluster_name", b"tagline"
    ],

    "Kubernetes API": [
        b"kubernetes", b"/api"
    ],

    "Docker": [
        b"Docker", b"API-Version"
    ],

    "Memcached": [
        b"STAT", b"ERROR"
    ],

    "AMQP (RabbitMQ)": [
        b"AMQP"
    ],

    "MQTT": [
        b"MQTT"
    ],

    "Git": [
        b"git", b"repository"
    ],
}
def Conn(ip,port,open_port):
    #Build ip and target port connection
    sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect((ip,port))
        open_port[port]["status"]="open"
    except ConnectionRefusedError:
        open_port[port]["status"]="closed"
    except ConnectionResetError:
        open_port[port]["status"]="closed"
    except socket.timeout:
        open_port[port]["status"]="filtered"        
    except OSError as e:         
        code = getattr(e, "winerror", None)
        if code in [10051, 10065]:
            open_port[port]["status"] = "unreachable"            
        else:
            open_port[port]["status"] = "filtered"
    finally:
        sock.close()
            
def dns(target):
    #DNS resolution of a domain
    print(target)
    try:
        ip=socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        return "DNS failed"
    
def Check_open(target,b,e,th):
    # Check target which port can have TCP connection
    ip=dns(target)
    print(ip)
    # Save the result of the scan target
    open_port = {}
    for port in range(b,e+1):
        open_port[port] = {
            "status": None,
            "service": None,
            "reason": None
            }
    with ThreadPoolExecutor(max_workers=th) as executor:
        for port in range(b, e+1):
            executor.submit(Conn, ip, port, open_port)
    return open_port

def check_banner(target,b,e,th):
    # banner the port's service which is opened
    open_port=Check_open(target,b,e,th)
    ip=dns(target)
    if(ip == "DNS failed"):
        return "DNS failed"

    for port in range(b,e+1):
        if open_port[port]["status"] != "open":
            continue
        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(2)
        try:

            try:
                sock.connect((ip,port))
                
            except ConnectionRefusedError:
                open_port[port]["service"] = "unknown"
                open_port[port]["reason"] = "connect_refused"
                continue
            except ConnectionResetError:
                open_port[port]["service"] = "unknown"
                open_port[port]["reason"] = "connect_reset"
                continue
            except socket.timeout:
                open_port[port]["service"] = "unknown"
                open_port[port]["reason"] = "unknown"
                continue
            except OSError:
                open_port[port]["service"] = "unknown"
                open_port[port]["reason"] = "unknown"
                continue
            
            if port in [80, 443, 3000,5000,8000,8080,8081, 8888,9000]:
                result_Check_HTTP=Check_HTTP(open_port,sock,port)
                if(result_Check_HTTP!=False):
                    data=result_Check_HTTP
                    result_match_rules=match_rules(data)
                    open_port[port]["service"]=result_match_rules
                    continue
            try:
                data=sock.recv(200)
            except socket.timeout:
               # open_port[port]["status"] = "recv_timeout"
                open_port[port]["service"] = "unknown"
                continue
            except ConnectionResetError:
              #  open_port[port]["status"] = "closed"
                open_port[port]["service"] = "unknown"
                continue

            if not data:
                    try:
                        sock.send(b"\r\n")
                    except socket.timeout:
                        open_port[port]["service"]="unknown"
                        open_port[port]["reason"] = "send_timeout"
                        continue
                    except ConnectionResetError:
                        open_port[port]["status"]="closed"
                        open_port[port]["service"] = "unknown"
                        open_port[port]["reason"] = "send_timeout"
                        continue
                    except BrokenPipeError:
                        open_port[port]["service"] = "unknown"
                        open_port[port]["reason"]= "broken_pipe"
                        continue
                    except OSError:
                        open_port[port]["service"] = "unknown"
                        open_port[port]["reason"]= "OSError"
                        continue
                    try:
                        data=sock.recv(200)
                    except socket.timeout:
                        open_port[port]["service"]="unknown"
                        open_port[port]["reason"] = "recv_timeout"
                        continue
                    except ConnectionResetError:
                        open_port[port]["status"]="closed"
                        open_port[port]["service"] = "unknown"
                        open_port[port]["reason"] = "unknown"
                        continue
                    if not data:
                       # open_port[port]["status"]="peer_closed"
                        open_port[port]["service"] = "unknown"
                        open_port[port]["reason"] = "peer_closed"
                        continue
                    else:
                        result_match_rules=match_rules(data)
                        open_port[port]["service"]=result_match_rules
                        continue
                
                    
            result_match_rules=match_rules(data)
            open_port[port]["service"]=result_match_rules
        finally:
            sock.close()    
    return open_port

def match_rules(data):
    # Check the recieve data match which rules
    for servers, patterns in RULES.items():
        for p in patterns:
            if p in data:
                return servers
    return "unknown" 
       
def Check_HTTP(open_port,sock,port):
    # Check the servive is Http
    try:
        sock.send(b"GET / HTTP/1.0\r\n\r\n")
    except socket.timeout:
        open_port[port]["service"] = "unknown"
        open_port[port]["reason"] = "send_timeout"
        return False
    except ConnectionResetError:
        open_port[port]["service"] = "unknown"
        open_port[port]["reason"] = "send_reset"
        return False
    except BrokenPipeError:
        open_port[port]["service"] = "unknown"
        open_port[port]["reason"] = "broken_pipe"
        return False
    except OSError:
        open_port[port]["service"] = "unknown"
        open_port[port]["reason"] = "send_error"
        return False
    try:
        data=sock.recv(200)
    except socket.timeout:
        open_port[port]["service"] = "unknown"
        open_port[port]["reason"] = "recv_timeout"
        return False
    except ConnectionResetError:
        open_port[port]["service"] = "unknown"
        open_port[port]["reason"] = "recv_reset"
        return False
    if not data:
        open_port[port]["service"] = "unknown"
        open_port[port]["reason"] = "no_banner"
        return False
    return data