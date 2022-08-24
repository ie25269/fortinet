import requests, sys, os, getopt
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import base64, json, pprint
#
# INFO
#  Show or Search fortigate central snat map entries.
# REFERENCE
#  API v6.2.8
#   https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/942/1/system/
#  Advanced Filtering:
#   https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/597/

def printhelp():
    print(f'\nDESCRIPTION:\n This script displays policies matching user defined search text')
    print(f'\nUSAGE:\n python3 <scriptName> -c(compact) -s <searchText> -v <vdom>\n  -s[OPTIONAL]  -v[OPTIONAL] -c[OPTIONAL]\n\n')

# ENV variables for auth.
env1 = "FORTI_HOST"
env2 = "FORTI_PORT"
env3 = "FORTI_KEY"
if env1 in os.environ:
    fortiIP = os.environ.get(env1)
if env2 in os.environ:
    fortiPort = os.environ.get(env2)
if env3 in os.environ:
    fortiKey = os.environ.get(env3)

# Set default search strings
searchVdom = "root"
searchTxt = ""
# Limit search results in case user does not specify
searchCount = "&count=20"
searchWarning = "\n * * * SEARCH RESULTS LIMITED to 20 by Default. Use -s option to filter results. * * *"
searchFooter = " (SEARCH RESULTS LIMITED to 20 by Default.)"
compactResults = "no"

# Parse arguments
argList = sys.argv[1:]
options = "hv:s:c"
try:
    args, value = getopt.getopt(argList, options)
    for arg, val in args:
        if arg in ("-h"):
            printhelp()
            sys.exit()
        elif arg in ("-s"):
            searchTxt = val
            searchCount = ""
            searchWarning = ""
            searchFooter = ""
        elif arg in ("-v"):
            searchVdom = val
        elif arg in ("-c"):
            compactResults = "yes"
except getopt.error as err:
    print("\nError: " , str(err) , "\n")
    sys.exit()

# SET Headers
myHeaders = {
    'accept': "application/json",
    'content-type': "application/json",
    'cache-control': "no-cache",
    }
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
ses = requests.session()
ses.verify = False
ses.disable_warnings = False
ses.timeout = 5

urlPath = "firewall/policy"
fortiToken = "?access_token=" + fortiKey
searchFormat = ""
searchFilter = ""
searchFilter = "&filter=name=@{0},policyid=@{0},srcaddr=@{0},dstaddr=@{0},comments=@{0},srcintf=@{0},dstintf=@{0}".format(searchTxt)
searchVdom = "&vdom={0}".format(searchVdom)
searchString = searchVdom + searchCount + searchFilter + searchFormat

url = 'https://{0}:{1}/api/v2/cmdb/{2}/{3}{4}'.format(fortiIP,fortiPort,urlPath,fortiToken,searchString)
res = ses.get(url, headers=myHeaders, verify=False)
content = res.content
data = json.loads(content)
headers = res.headers
statcode = res.status_code
print(f'\n\n{fortiIP}:{fortiPort}\n--------------------')

vdom = data['vdom']
subdata = data['results']
numResults = len(subdata)

# Output Header
print(f'{searchWarning}\n')

for obj in subdata:
    policyID = obj['policyid']
    action = obj['action']
    ruleStatus = "(" + obj['status'] + ")"
    name = obj['name']
    utm = obj['utm-status']
    nat = obj['nat']
    comments = obj['comments']
    secProfiles = []
    uuid = obj['uuid']
    logging = obj['logtraffic']
    service, srcintf, dstintf, srcaddr, dstaddr, profiles = "", "", "", "", "", ""

    if obj['av-profile']:
        secProfiles.append(str(obj['av-profile']))
    if obj['webfilter-profile']:
        secProfiles.append(str(obj['webfilter-profile']))
    if obj['dnsfilter-profile']:
        secProfiles.append(str(obj['dnsfilter-profile']))
    if obj['ssl-ssh-profile']:
        secProfiles.append(str(obj['ssl-ssh-profile']))
    if obj['ips-sensor']:
        secProfiles.append(str(obj['ips-sensor']))
    if obj['application-list']:
        secProfiles.append(str(obj['application-list']))

    for i in secProfiles:
        profiles = str(i) + " " + profiles
    for i in obj['service']:
        service = (i['name'] + " " + service) if 'name' in i else ""
    for i in obj['srcintf']:
        srcintf = i['name'] + " " + srcintf
    for i in obj['dstintf']:
        dstintf = i['name'] + " " + dstintf
    for i in obj['srcaddr']:
        srcaddr = i['name'] + "," + srcaddr
    for i in obj['dstaddr']:
        dstaddr = i['name'] + "," + dstaddr

    # COMPACT Results
    if compactResults == "yes":
        if len(name) > 30:
            name = name[0:30] + "..."
        if len(service) > 15:
            service = service[0:12] + "..."
        if len(srcaddr) > 26:
            srcaddr = srcaddr[0:23] + "..."
        if len(dstaddr) > 26:
            dstaddr = dstaddr[0:23] + "..."
        print(f'{policyID:<6} {ruleStatus:<9} {name:<34} {action:<6} {srcintf:<8}> {dstintf:<8} {srcaddr:<27}> {dstaddr:<27}  {service:<15} ')
    else:
    #elif compactResults == "no":
    # LONG Detailed Results
        print(f'\nRule-ID: {policyID:<6} {ruleStatus:<8}  RuleName: {name:<40}  uuid:{uuid:>20}')
        print(f'    Action:  {action}')
        print(f'    SrcIntf: {srcintf}')
        print(f'    SrcAddr: {srcaddr}')
        print(f'    DstIntf: {dstintf}')
        print(f'    DstAddr: {dstaddr}')
        print(f'    Service: {service}')
        print(f'    SecProf: {profiles}')
        print(f'    Logging: {logging}')


print(f'\n--------------------')
print(f'RESULTS: {numResults}   {searchFooter}')
print(f'vdom: {vdom}')
print(f'Stat-Code: {statcode}')
print(f'{urlPath}{searchString}')
print(f'\n\n')

