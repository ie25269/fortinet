import requests, sys, os, getopt
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import base64, json, pprint
#
# INFO
#  Search fortigate address object names/subnets/comments and return results if a match is found.
# REFERENCE
#  API v6.2.8
#   https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/942/1/system/
#  Advanced Filtering:
#   https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/597/

def printhelp():
    print(f'\nDESCRIPTION:\n This script searches fortigate addressgroup object names/member-names/comments and return results if a match is found.')
    print(f'\nUSAGE:\n python3 <scriptName> -s <searchText> -v <vdom> -d <detailedResults>\n  -s[REQUIRED]  -v[OPTIONAL] -d [OPTIONAL]\n\n')

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
options = "hdv:s:"
searchVdom = "root"
searchTxt = ""
detailedResults = "n"

if len(argList) < 1:
    print(f'\n----------\nError: must supply arguments -s <searchText> \n----------\n')
    sys.exit()
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
        elif arg in ("-d"):
            detailedResults = "y"
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

urlPath = "firewall/addrgrp"
fortiToken = "?access_token=" + fortiKey
searchFormat = ""
searchFilter = "&filter=name=@{0},comment=@{0},member=@{0}".format(searchTxt)
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
results = data['results']
numResults = len(results)
# print data header based on detailedResults arg
if detailedResults == "n":
    print(f' NAME                                #MEMBERS   COMMENT')
for obj in results:
    name = obj['name']
    comment = obj['comment']
    uuid = obj['uuid']
    memList = obj['member']
    numMembers = len(memList)
    if detailedResults == "n":
        print(f' {name:<35} {numMembers:>6}     {comment}')
    else:
        print(f' {name}  ({comment})')
        print(f'   members:')
        x = 1
        for mem in memList:
            memName = mem['name']
            print('   {0:>5}.  {1}'.format(str(x),memName))
            x += 1
        print(f'\n')


print(f'\n--------------------')
print(f'RESULTS: {numResults}')
print(f'vdom: {vdom}')
print(f'Stat-Code: {statcode}')
print(f'{urlPath}{searchString}')
print(f'\n\n')

