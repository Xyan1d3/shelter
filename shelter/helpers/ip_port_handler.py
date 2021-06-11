from shelter.helpers.stylize import *

import netifaces
import subprocess

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