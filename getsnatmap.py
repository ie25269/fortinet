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
    print(f'\nDESCRIPTION:\n This script displays central snat map entries')
    print(f'\nUSAGE:\n python3 <scriptName> -s <searchText> -v <vdom>\n  -s[OPTIONAL]  -v[OPTIONAL] \n\n')

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

# Parse arguments
argList = sys.argv[1:]
options = "hv:s:"
searchVdom = "root"
searchTxt = ""

try:
    args, value = getopt.getopt(argList, options)
    for arg, val in args:
        if arg in ("-h"):
            printhelp()
            sys.exit()
        elif arg in ("-s"):
            searchTxt = val
        elif arg in ("-v"):
            searchVdom = val
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

urlPath = "firewall/central-snat-map"
fortiToken = "?access_token=" + fortiKey
searchFormat = ""
searchFilter = "&filter=orig-addr=@{0},dst-addr=@{0},nat-ippool=@{0},comments=@{0},srcintf=@{0},dstintf=@{0}".format(searchTxt)
searchVdom = "&vdom={0}".format(searchVdom)
searchString = searchVdom + searchFilter + searchFormat 

url = 'https://{0}:{1}/api/v2/cmdb/{2}/{3}{4}'.format(fortiIP,fortiPort,urlPath,fortiToken,searchString)
res = ses.get(url, headers=myHeaders, verify=False)
content = res.content
data = json.loads(content)
headers = res.headers
statcode = res.status_code
print(f'\n\n{fortiIP}:{fortiPort}\n--------------------\n')

vdom = data['vdom']
subdata = data['results']
numResults = len(subdata)
for obj in subdata:
    policyID = obj['policyid']
    status = obj['status']
    comments = obj['comments']
    srcport = obj['orig-port']
    dstport = obj['nat-port']
    natstat = obj['nat']
    natport = obj['nat-port']
    proto = obj['protocol']
    print(f'\nPolicyID# {policyID:<8} ruleStatus={status:<12} {comments}')

    srcaddr=""
    for i in obj['orig-addr']:
        name = i['name']
        srcaddr = name + " " + srcaddr 

    dstaddr=""
    for i in obj['dst-addr']:
        name = i['name']
        dstaddr = name + " " + dstaddr

    srcintf=""
    for i in obj['srcintf']:
        name = i['name']
        srcintf = name + " " + srcintf

    dstintf=""
    for i in obj['dstintf']:
        name = i['name']
        dstintf = name + " " + dstintf

    natpool=""
    for i in obj['nat-ippool']:
        name = i['name']
        natpool = name + " " + natpool

    srcString = "src-addr: {0}\n src-intf: {1}\n src-port: {2}".format(srcaddr,srcintf,srcport)
    dstString = "dst-addr: {0}\n dst-intf: {1}\n dst-port: {2}".format(dstaddr,dstintf,dstport)
    natString = "nat-stat: {0}\n nat-port: {1}\n nat-pool: {2}".format(natstat,natport,natpool)
    protoString = "protocol: {0}".format(proto)

    print(f' {srcString}')
    print(f' {dstString}')
    print(f' {protoString}')
    print(f' {natString}')


print(f'\n--------------------')
print(f'RESULTS: {numResults}')
print(f'vdom: {vdom}')
print(f'Stat-Code: {statcode}')
print(f'{urlPath}{searchString}')
print(f'\n\n')

