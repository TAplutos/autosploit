# here we store a list of vulnerabilities our software will be able to exploit
# description of the exploit's keywords must be comma separated
# module name is the module name used in metasploit
class Vulnerability():
    def __init__(self, keywords, minKeyTermsThatMustMatch, caseSensitiveKeyTermMatch, moduleName, description, payload = None):
        self.keywords = keywords.split(",")
        self.minKeyTermsThatMustMatch = minKeyTermsThatMustMatch
        self.caseSensitiveKeyTermMatch = caseSensitiveKeyTermMatch
        self.module = moduleName
        self.description = description
        self.payload = payload


# TO ADD A NEW VULNERABILITY
# 1) add its keywords, min number of key terms to be matched, moduleName, a short description here, and a payload if the exploit has one
# DO NOT ADD ANY EXTRA SPACES.  
# GOOD: "Apache Tomcat,rce,Port 444"
# BAD: "Apache Tomcat, rce, Port 444"
# 2) ADD THE VARIABLE YOU MAKE TO THE LIST BELOW
# 3) TODO: configure this shit to work CORRECTLY with payloads
ircd = Vulnerability("UnrealIRCd,irc,6667", 2, True, "unix/irc/unreal_ircd_3281_backdoor", "unreal ircd backdoor RCE", 'cmd/unix/bind_ruby')
distcc = Vulnerability("distcc,3632", 2, False, "unix/misc/distcc_exec", "distcc RCE")

vulnerabilities = [ircd, distcc]