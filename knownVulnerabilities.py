# here we store a list of vulnerabilities our software will be able to exploit
# description of the exploit's keywords must be comma separated
# module name is the module name used in metasploit
# TODO: CHANGE THIS TO HAVE A DICTIONARY FOR EVERYTHING
class Vulnerability():
    def __init__(self, classDict):
        # THESE ARE MUST HAVES FOR EVERY EXPLOIT
        self.keywords = classDict["keywords"].split(",")
        self.minKeyTermsThatMustMatch = classDict["minKeyTermsThatMustMatch"]
        self.caseSensitiveKeyTermMatch = classDict["caseSensitiveKeyTermMatch"]
        self.module = classDict["moduleName"]
        self.description = classDict["description"]
        self.exploitType = classDict["exploitType"]
        # THESE ARE MAYBE's FOR EACH EXPLOIT, SOME DONT USE PAYLOADS, SLEEP TIME...etc
        if "payload" in classDict: self.payload = classDict["payload"]
        else: self.payload = None
        # This is the amount of time the exploit should take to run.  Mutliple exploits should 
        # not run at the same time, one should finish before the next is run hence this timer
        if "sleep" in classDict: self.sleep = classDict["sleep"]
        else: self.sleep = 10
        self.session = None # TODO: create a method to set and get this


# TO ADD A NEW VULNERABILITY
# 1) add its keywords, min number of key terms to be matched, moduleName, a short description here, and a payload if the exploit has one
# DO NOT ADD ANY EXTRA SPACES.  
# GOOD: "Apache Tomcat,rce,Port 444"
# BAD: "Apache Tomcat, rce, Port 444"
# 2) ADD THE VARIABLE YOU MAKE TO THE LIST BELOW
# 3) TODO: configure this shit to work CORRECTLY with payloads

_ircdDict = {
    "keywords": "UnrealIRCd,irc,6667",
    "minKeyTermsThatMustMatch": 2,
    "caseSensitiveKeyTermMatch": True,
    "moduleName": "unix/irc/unreal_ircd_3281_backdoor",
    "description": "unreal ircd backdoor RCE",
    "exploitType": "exploit",
    "payload": "cmd/unix/bind_ruby"
    } 
_ircd = Vulnerability(_ircdDict)

_distccDict = {
    "keywords": "distcc,3632",
    "minKeyTermsThatMustMatch": 2,
    "caseSensitiveKeyTermMatch": False,
    "moduleName": "unix/misc/distcc_exec",
    "description": "distcc RCE",
    "exploitType": "exploit",
    "payload": "cmd/unix/bind_ruby",
    "sleep": 20
    } 
_distcc = Vulnerability(_distccDict)

_vsftpdDict = {
    "keywords": "21,vsftpd",
    "minKeyTermsThatMustMatch": 2,
    "caseSensitiveKeyTermMatch": False,
    "moduleName": "unix/ftp/vsftpd_234_backdoor",
    "description": "vsftpd backdoor RCE",
    "exploitType": "exploit",
    "payload": "cmd/unix/interact",
    "sleep": 20
    } 
_vsftpd = Vulnerability(_vsftpdDict)

# doesnt work yet idk why
_smtpScannerDict = {
    "keywords": "25,smtp",
    "minKeyTermsThatMustMatch": 2,
    "caseSensitiveKeyTermMatch": False,
    "moduleName": "scanner/smtp/smtp_enum",
    "description": "SMTP scanner for user enumeration",
    "exploitType": "auxiliary",
    "payload": None,
    "sleep": 1500
    } 
_smtpScanner= Vulnerability(_smtpScannerDict)

vulnerabilities = [_ircd, _distcc, _vsftpd, _smtpScanner]