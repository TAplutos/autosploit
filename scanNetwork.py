import utils
import re

# runs ip addr and then extracts the ip addresses and returns those as a list of strings
def _scanNetwork(pattern):
    result = utils.runThisCommand("ip addr")
    ips = []
    for line in result:
        ip = re.search(pattern, line)
        if ip:
            ips.append(ip[0][5:])
    return ips

def scanNetworkForIPs():
    return _scanNetwork("inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+")

def scanNetworkForIPRanges():
    return _scanNetwork("inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]*")