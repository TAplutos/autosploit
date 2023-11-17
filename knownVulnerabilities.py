# here we store a list of vulnerabilities our software will be able to exploit
# description of the exploit's keywords must be comma separated
# module name is the module name used in metasploit
# TODO: CHANGE THIS TO HAVE A DICTIONARY FOR EVERYTHING
class Vulnerability():
    def __init__(self, classDict):
        # If any of these terms match, the exploit is run
        self.keywords = classDict["keywords"].split(",")
        # if at least minOptionalKeyTermsThatMustMatch of these terms match, the exploit is run
        self.optionalKeywords = classDict["optionalKeywords"].split(",")
        self.minOptionalKeyTermsThatMustMatch = classDict["minOptionalKeyTermsThatMustMatch"]
        self.caseSensitiveKeyTermMatch = classDict["caseSensitiveKeyTermMatch"]
        self.module = classDict["moduleName"]
        self.description = classDict["description"]
        self.exploitType = classDict["exploitType"]
        # This is the amount of time the exploit should take to run.  Mutliple exploits should 
        # not run at the same time, one should finish before the next is run hence this timer
        self.maxRuntime = classDict["maxRuntime"]
        # THESE ARE MAYBE's FOR EACH EXPLOIT, SOME DONT USE PAYLOADS, MAX RUN TIME...etc
        if "payload" in classDict: self.payload = classDict["payload"]
        else: self.payload = None
        if "canCheck" in classDict: self.canCheck = classDict["canCheck"]
        else: self.canCheck = True
        if "outputPatternMatch" in classDict: self.outputPatternMatch = classDict["outputPatternMatch"]
        else: self.outputPatternMatch = None
        # will this exploit get us a list of usernames to use
        if "addUserNames" in classDict: self.addUserNames = classDict["addUserNames"]
        else: self.addUserNames = False

        # run options for the module
        if "options" in classDict:
            options = classDict["options"]
            self.options = dict()
            for (key,value) in options:
                self.options[key] = value
        else:
            self.options = None

        self.session = None # TODO: create a method to set and get this


# TO ADD A NEW VULNERABILITY
# 1) add its keywords, min number of key terms to be matched, moduleName, a short description here, and a payload if the exploit has one
# DO NOT ADD ANY EXTRA SPACES.  
# GOOD: "Apache Tomcat,rce,Port 444"
# BAD: "Apache Tomcat, rce, Port 444"
# 2) ADD THE VARIABLE YOU MAKE TO THE LIST BELOW
# 3) TODO: configure this shit to work CORRECTLY with payloads

_ircdDict = {
    "keywords": "UnrealIRCd",
    "optionalKeywords": "irc,6667",
    "minOptionalKeyTermsThatMustMatch": 2,
    "caseSensitiveKeyTermMatch": True,
    "moduleName": "unix/irc/unreal_ircd_3281_backdoor",
    "description": "unreal ircd backdoor RCE",
    "exploitType": "exploit",
    "payload": "cmd/unix/bind_ruby",
    "outputPatternMatch": "shell session [0-9]* opened.*",
    "maxRuntime": 20
    } 
_ircd = Vulnerability(_ircdDict)

_distccDict = {
    "keywords": "distcc",
    "optionalKeywords": "3632",
    "minOptionalKeyTermsThatMustMatch": 2,
    "caseSensitiveKeyTermMatch": False,
    "moduleName": "unix/misc/distcc_exec",
    "description": "distcc RCE",
    "exploitType": "exploit",
    "payload": "cmd/unix/bind_ruby",
    "outputPatternMatch": "shell session [0-9]* opened.*",
    "maxRuntime": 20
    } 
_distcc = Vulnerability(_distccDict)

_vsftpdDict = {
    "keywords": "vsftpd",
    "optionalKeywords": "21,ftp",
    "minOptionalKeyTermsThatMustMatch": 2,
    "caseSensitiveKeyTermMatch": False,
    "moduleName": "unix/ftp/vsftpd_234_backdoor",
    "description": "vsftpd backdoor RCE",
    "exploitType": "exploit",
    "payload": "cmd/unix/interact",
    "outputPatternMatch": "shell session [0-9]* opened.*",
    "maxRuntime": 20
    } 
_vsftpd = Vulnerability(_vsftpdDict)

# doesnt work yet idk why
_smtpScannerDict = {
    "keywords": "smtp",
    "optionalKeywords": "25",
    "minOptionalKeyTermsThatMustMatch": 2,
    "caseSensitiveKeyTermMatch": False,
    "moduleName": "scanner/smtp/smtp_enum",
    "description": "SMTP scanner for user enumeration",
    "exploitType": "auxiliary",
    "payload": None,
    "outputPatternMatch": "Users found:.*",
    "canCheck": False,
    "maxRuntime": 1500
    } 
_smtpScanner= Vulnerability(_smtpScannerDict)

_mysqlBruteForceDict = {
    "keywords": "",
    "optionalKeywords": "3306,mysql,Support41Auth",
    "minOptionalKeyTermsThatMustMatch": 2,
    "caseSensitiveKeyTermMatch": True,
    "moduleName": "scanner/mysql/mysql_login",
    "description": "SQL login spam",
    "exploitType": "auxiliary",
    "payload": None,
    "outputPatternMatch": "MYSQL - Success: .*",
    "addUserNames": True,
    "maxRuntime": 10000,
    "options": [("ANONYMOUS_LOGIN", True),
                ("BLANK_PASSWORDS", True),
                ("DB_ALL_PASS", True),
                ("DB_ALL_USERS", True),
                ("USER_AS_PASS", True),
                ("VERBOSE", True),
                ("USER_FILE", "USERNAMES.txt"),
                ("PASS_FILE", "PASSWORDS.txt"),
                ("USERPASS_FILE", "")]
    }
_mysqlBruteForce = Vulnerability(_mysqlBruteForceDict)

vulnerabilities = [_ircd, _distcc, _vsftpd, _smtpScanner, _mysqlBruteForce]