from shelter.helpers.stylize import *

import os

def shell_handler(port,proto=None,nohandler=False): # shell_handler invokes a netcat listener it takes port to listen on and protocol UDP/TCP
    if not nohandler:
        ap("Starting up Shell Handler...")
        if proto == None or proto.lower() == "tcp":
            os.system(f"nc -lvnp {port}") # Invoking netcat as TCP listener
        else:
            os.system(f"nc -luvnp {port}") # Invoking netcat with UDP support
    else:
        ainfo("No Handler flag detected. Handler will not be started.")