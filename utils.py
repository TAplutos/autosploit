# for utility functions
# can grab characters after a word, run a command
#test
import subprocess

default_passwords = ["admin","manager","role1","root","tomcat","s3cret","vagrant","QLogic66","password","Password1","changethis","r00t","toor","password1","j2deployer","OvW*busr1","kdsxc","owaspba","ADMIN","xampp"]
default_usernames = ["admin","manager","role1","role","root","tomcat","both","QCC","j2deployer","ovwebusr","cxsdk","ADMIN","xampp"]

def runThisCommand(command):
    command = command.split()
    result = subprocess.run(command, stdout=subprocess.PIPE)
    ret = []
    for line in result.stdout.splitlines():
        ret.append(str( line, 'utf-8' ))
    return ret
# for testing the above
# print(runThisCommand("nmap scanme.nmap.org"))

# takes input and word and returns indexes of all occurences of word in string
def grepPositions(input_str, word):
    positions = []
    start = 0

    while True:
        start = input_str.find(word, start)
        if start == -1:
            break
        positions.append(start)
        start += 1  # Move to the next character to search for overlapping occurrences

    return positions

def getSuccessMessage(output): 
    for i in range(len(output)):
        if output[i] == "*" and i >= 30:
            output = output[i-1:]
            break
    
    # del arrayOutput[-2:]
    return output

def extractResult(output): 
    arrayOutput = output.splitlines()
    for index,line in enumerate(arrayOutput):
        if("DisablePayloadHandler" in line):
            del arrayOutput[:index+1]
    
    # del arrayOutput[-2:]
    return arrayOutput

# returns an array of all characters between a and b positions after every occurence of word in input
# e.g. input = '<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ssh" method="table " conf="3"/></port> <port protocol="tcp" portid="99"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="nping-echo" method="table" conf="3"/></'
# word = portid
# a = 8
# b = 10
# returns [22,99]
def grepAfter(input, word, a, b):
    positions = grepPositions(input,word)
    ret = []
    for i in positions:
        if i + b <= len(input):
            ret.append(input[i + a: i + b])
    return ret
# tests the above
# grepAfter('<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ssh" method="table " conf="3"/></port> <port protocol="tcp" portid="99"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="nping-echo" method="table" conf="3"/></', "portid", 8, 10)

# same as above but returns all characters in input after word starting at character a and ending at b
# e.g. input = '<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ssh" method="table " conf="3"/></port> <port protocol="tcp" portid="99"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="nping-echo" method="table" conf="3"/></'
# word = portid
# a = "
# b = "
# returns [22,99]
def grepBetween(input, word, a, b):
    positions = grepPositions(input,word)
    ret = []
    for i in positions:
        start = input.find(a, i)
        end = input.find(b, start + 1)
        if start == -1:
            break
        if end == -1:
            end = len(input)
        ret.append(input[start + 1: end])
    print(ret)
    return ret
# tests the above
# grepBetween('<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ssh" method="table " conf="3"/></port> <port protocol="tcp" portid="99"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="nping-echo" method="table" conf="3"/></', "portid", "\"", "\"")