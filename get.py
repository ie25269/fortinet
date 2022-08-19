import requests, sys, os, getopt
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import base64, json, pprint
#
# INFO
#  Runs a simple get request against your fortinet device and prints the results.
#  Useful for testing your ENV variables, api key, or as a template for building other scripts.
# REFERENCE
#  https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/93

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
#        elif arg in ("-s"):
#            searchTxt = val
#        elif arg in ("-v"):
#            searchVdom = val
except getopt.error as err:
    print("\nError: " , str(err) , "\n")
    sys.exit()

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

fortiToken = "?access_token=" + fortiKey
searchFormat = ""
searchFilter = ""
searchString = ""
#searchFilter = "&filter=orig-addr=@{0},dst-addr=@{0},nat-ippool=@{0},comments=@{0},srcintf=@{0},dstintf=@{0}".format(searchTxt)
#searchVdom = "&vdom={0}".format(searchVdom)
#searchString = searchVdom + searchFilter + searchFormat
# URL path for the request; exclude the leading & trailing separators
urlPath = "system/fortiguard"
url = 'https://{0}:{1}/api/v2/cmdb/{2}/{3}{4}'.format(fortiIP,fortiPort,urlPath,fortiToken,searchString)

res = ses.get(url, headers=myHeaders, verify=False)
content = res.content
data = json.loads(content)
headers = res.headers
statcode = res.status_code
print(f'\n\n{fortiIP}:{fortiPort}\n--------------------\n')

# UNCOMMENT below line to print response
#print(f'{res}')
# UNCOMMENT below line to print response headers
#print(f'{headers}')
# UNCOMMENT below line to print returned data in raw format
#print(f'{content}')
# UNCOMMENT below line to print returned data json format
pprint.pprint(data, indent=2)



print(f'\n--------------------')
print(f'vdom: {searchVdom}')
print(f'Stat-Code: {statcode}')
print(f'{urlPath}{searchString}')
print(f'\n\n')

