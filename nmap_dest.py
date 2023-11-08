# this file is for automating nmap output 
import utils

def nmap_xml_output(dest = "scanme.nmap.org", args = "-oX -"):
    # this runs the command "nmap -oX - scanme.nmap.org"
    print("running command: " + 'sudo nmap ' + args + ' ' + str(dest))
    result = utils.runThisCommand('sudo nmap ' + args + ' ' + str(dest))
    print("NMAP scan finished")
    return result
# for testing the above
# nmap_xml_output("scanme.nmap.org")