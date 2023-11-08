# this file is for automating nmap output 
import utils

def nmap_xml_output(dest = "scanme.nmap.org"):
    # this runs the command "nmap -oX - scanme.nmap.org"
    result = utils.runThisCommand('nmap -oX - ' + str(dest))
    return result
# for testing the above
# nmap_xml_output("scanme.nmap.org")