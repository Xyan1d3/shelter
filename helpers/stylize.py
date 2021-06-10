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
def ainfo(text) :
    print(f"{bold}{purple}[*] {end}{text}")
def aerr(text) : 
    print(f"{bold}{red}[-] {end}{text}") 