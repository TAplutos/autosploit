from pymetasploit3.msfrpc import *
import utils
import sys

if __name__ == "__main__":
    # initial setup
    # UNCOMMENT THIS IF SHIT ISNT WORKING
    # try:
    #     utils.runThisCommand("msfrpcd -P PASSWORD")
    # except:
    #     sys.path.append('/snap/bin')
    #     utils.runThisCommand("msfrpcd -P PASSWORD")
    
    client = MsfRpcClient('Trevor34', port=55553, ssl=True)
    # exploit = client.modules.use('exploit', 'unix/ftp/vsftpd_234_backdoor')
    
    print(client.modules.exploits)

    # print("Running autosploit, input ip or website to exploit: ", end="")
    # RHOST = input()
    print("done")
    