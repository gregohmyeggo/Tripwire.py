import imports

## Reads in Tripwire environment variables from yaml file. 
stream = open('environment.yml', 'r')
data = imports.yaml.safe_load(stream)


## Adds a comment to the case; used for C2 command logging.
def addComment(caseID, comment):

    # https://www.elastic.co/guide/en/kibana/master/cases-api-add-comment.html#_request_body_2
    data = {
        "comment": comment,
        "owner": "securitySolution",
        "type": "user"
    }

    url = f"{imports.variables.kibana_url}/cases/{caseID}/comments"
    r = imports.requests.post(url, headers=imports.variables.elk_headers, data=imports.json.dumps(data))
    
    return r.status_code


## Attaches alerts to the case container for each session
# |__ https://www.elastic.co/guide/en/kibana/master/cases-api-add-comment.html
def attachAlerts(caseID, _id, _index, rule_id, rule_name):
    
    # https://www.elastic.co/guide/en/kibana/master/cases-api-update.html#_request_body_5
    data = {
        "alertId": _id,
        "index": _index,
        "owner": "securitySolution",
        "rule":{
            "id": rule_id,
            "name": rule_name
        },
        "type": "alert"
    }

    url = f"{imports.variables.kibana_url}/cases/{caseID}/comments"
    r = imports.requests.post(url, headers=imports.variables.elk_headers, data=imports.json.dumps(data))


## Prints a line of barbed wire; nothing more, nothing less.
def barbed_wire():
    w = imports.os.get_terminal_size()
    width = (int(w[0]))-1
    barbed_wire = ('\n'+ '*-' * (int(width/2))) + "*"
    # print(barbed_wire, "\n")
    print(barbed_wire)


## Prints the alert information
# NEEDS TO BE REWORKED
def base_alert(hit, name, uuid, timestamp, host):
    print('-' * (len(name)+6))
    print(f'Name: {name}')
    print(f'   * ID: {uuid}\n   * Timestamp: {timestamp}\n   * Hostname: {host}')
    print("")


## Checks if the script can reach ELK; used for the main menu "Lab" status indicator
def check_elk():
    r = imports.requests.get(imports.variables.elasticsearch_url, headers=imports.variables.elk_headers, verify=False)
    return True


## Clears console window
def clear_console():
    imports.os.system('cls' if imports.os.name == 'nt' else 'clear')


## Sets the case status to "Closed"
def closeCase(caseID):

    cases = getCases()
    for case in cases:
        
        # FOR DEBUGGING
        # if caseID in case['id']:
        #     print(f"{imports.colors.YELLOW}[DEBUG]{imports.colors.END}\n{imports.colors.DEBUG}{case}{imports.colors.END}\n")

        if caseID in case['id']:
            version = case['version']

    data = {
        "cases": [
            { 
            "id": caseID,
            "version": version,
            "status": "closed",
            }
        ]
    }

    url = f"{imports.variables.kibana_url}/cases"
    r = imports.requests.patch(url, headers=imports.variables.elk_headers, data=imports.json.dumps(data))


## Creates a Security Cases "case" to containerize any triggered alerts during the session.
# |__ OUTPUT: Case: <getWord()>
def createCase(name):
    timestamp = imports.datetime.today().strftime('%Y-%m-%d %H:%M:%S')
    url = f"{imports.variables.kibana_url}/cases"

    # A sloppy way to parse the provided arguments.
    if name == "None":
        name = get_word()
    elif name:
        name = name[0]
    else:
        name = get_word()

    # Base case creation template for the POST request
    #|__ https://www.elastic.co/guide/en/kibana/master/cases-api-create.html
    data = { 
        "assignees": [],
        "connector": {
            "id": "None",
            "name": "None",
            "type": ".none",
            "fields": None
        },
        "description": f"Started at {timestamp}", 
        "owner": "securitySolution", 
        "settings": { 
            "syncAlerts": True },
        "tags": [],
        "title": f"{name}"
    }
    
    r = imports.requests.post(url, headers=imports.variables.elk_headers, data=imports.json.dumps(data))
    return r.json()


## Pulls attached alerts (if any) from the caseID.
def getAlertsFromCase(caseID):
    url = f"{imports.variables.kibana_url}/cases/{caseID}/alerts"
    alerts = imports.requests.get(url, headers=imports.variables.elk_headers)
    return alerts.json()


## Returns case information from ELK; required for updating and closing the case.
def getCases():
    url = f"{imports.variables.kibana_url}/cases/_find"
    cases = imports.requests.get(url, headers=imports.variables.elk_headers)
    return cases.json()['cases']


# Fetches MITRE ATT&CK CTI data and returns techniques; used for "Technique Challenge"
def getTechnique(caseID):
    imports.logging.getLogger('taxii2client').setLevel(imports.logging.CRITICAL)

    lift = imports.attack_client()
    techniques = lift.get_techniques(include_subtechniques=False)

    all_techniques = []
    for t in techniques:
        all_techniques.append(imports.json.loads(t.serialize()))

    def get_random_technique():
        tactics = ['execution','persistence','privilege-escalation','defense-evasion','credential-access','discovery','lateral-movement']
        
        # DEBUG
        # print(f"\n{imports.colors.DEBUG}{len(all_techniques)}{imports.colors.END}")
        
        randotech = all_techniques[imports.random.randint(0, (len(all_techniques))-1)]

        if 'Windows' in randotech['x_mitre_platforms']:
        
            phases = []
            for kcp in randotech['kill_chain_phases']:
                phases.append(kcp['phase_name'])
            
            for tactic in tactics:
                if tactic in phases:
                    return randotech
                
    ## Loops until a suitable technique is returned
    technique = []
    while len(technique) == 0:
        randotech = get_random_technique()
        if randotech:
            technique.append(randotech['name'])
            # print(imports.json.dumps(randotech, indent=4))

            challenge = (f"**Technique Challenge:** _{randotech['name']}_")
                   
            addComment(caseID, challenge)
            print(f"\n[!] Technique Challenge: {imports.colors.PURPLE}{randotech['name']}{imports.colors.END}")


## Returns the specific case information per the given caseID
def findCase(caseID):
    url = f"{imports.variables.kibana_url}/cases/{caseID}"
    case = imports.requests.get(url, headers=imports.variables.elk_headers)
    return case.json()


'''
[+] Covenant
DLC Coming Soon!
'''   
def getCovenant():
    print("DLC Coming Soon!")
    return

## Returns virtual machine: 'id', 'cpu', and 'memory'
## |__ {'id': 'TIVDABE2T3UHP77E68P3ATJU195KS8KK', 'cpu': {'processors': 2}, 'memory': 4096}
def get_resources(vmid):

    resources = {
        'id': None,
        'processeors': None,
        'memory': None
    }

    url = f"{imports.variables.url}/vms/{vmid}"
    headers = imports.variables.headers

    req = imports.requests.get(url, headers=headers)
    json = req.json()

    for item in json:
        print(json[item])

## Returns a list of enabled|disabled detection rules, based on the provided state.
def getRules(state):
    rules = []
    url = f"{imports.variables.kibana_url}/alerting/rules/_find?per_page=10000"
    r = imports.requests.get(url, headers=imports.variables.elk_headers, verify=False)

    for rule in r.json()['data']:
        # rules.append(rule['name'])
        if rule['enabled'] == state:
            # print(f"{rule['name']}")
            rules.append(rule['name'])
    # print(f"{imports.colors.GREY}Enabled Rules: {len(rules)}{imports.colors.END}")
    return rules

'''
[+] Sliver
Requires Filebeat configuration monitoring <path-to>/.sliver-client/history
'''
def getSliver(command_ids, caseID, dt):
    r = imports.requests.get(imports.variables.filebeat_url, headers=imports.variables.fb_headers, verify=False)
    hits = r.json()
    for hit in hits['hits']['hits']:
        message = hit['_source']['message']
        if hit['_source']['log']['file']['path'] == '/root/.sliver-client/history':
            ts = hit['_source']['@timestamp']

            #if dt >= ts:
            if dt <= ts: # Working
            
                if len(command_ids) == 0:
                    # Adds the Sliver command to the case
                    comment = f"[SLIVER] {ts}\n{message}\n"
                    addComment(caseID, comment)

                    print(f"[SLIVER] {ts}\n{imports.colors.CYAN}{message}{imports.colors.END}\n")
                    if hit['_id']:
                        return hit['_id']
                    
                elif hit['_id'] not in command_ids:
                    # Adds the Sliver command to the case
                    comment = f"[SLIVER] {ts}\n{message}\n"
                    addComment(caseID, comment)

                    print(f"[SLIVER] {ts}\n{imports.colors.CYAN}{message}{imports.colors.END}\n")
                    if hit['_id']:
                        return hit['_id']

## Returns a list of VM IDs; used for interacting with the /vms endpoint.
def get_VMids():
    vmids = []
    url = f"{imports.variables.url}/vms"
    headers = imports.variables.headers

    req = imports.requests.get(url, headers=headers)

    for _id in req.json():
        if imports.variables.vm_path in _id['path']:
            vmids.append(_id)

    return vmids

## Returns a list of virtual machine .VMX files; required to shutdown virtual machines via vmrun.exe.
def getVMX():
    files = []
    path = data['ENVIRONMENT']['VM_PATH']

    for directory in imports.os.listdir(path):

        subdir = imports.os.listdir(f"{path}\\{directory}")

        for file in subdir:
            if file.endswith(".vmx"):
                vmx = f"{path}\\{directory}\\{file}"
                files.append(vmx)
                
    return files

## Random adj-verb-noun generator; case name generation
def get_word():

    adj=["melodic", "tall", "abrasive", "afraid", "understood", "omniscient", "tangible", "absorbed", "curvy", "defeated", "repulsive", "low", "comprehensive", "wicked", "dashing", "ancient", "vigorous", "nifty", "questionable", "high"]
    verb=["peer", "return", "absorb", "claim", "present", "appoint", "stage", "blow", "pack", "persuade", "sound", "boost", "coincide", "underline", "bear", "ride", "see", "register", "attain", "vary"]
    noun=["tea", "art", "understanding", "initiative", "efficiency", "success", "gate", "instruction", "engineering", "economics", "series", "indication", "decision", "suggestion", "lake", "examination", "atmosphere", "movie", "football", "blood"]

    _adj = imports.random.choice(adj)
    _verb = imports.random.choice(verb)
    _noun = imports.random.choice(noun)

    word = f"{_adj}-{_verb}-{_noun}"
    return word


## Prints Tripwire information page
def information():
    print(f"{imports.colors.RED}Tripwire{imports.colors.END} is a bring-your-own-virtual machine orchestration script",
            f"designed to suppliment",
            f"[{imports.colors.RED}Red{imports.colors.END}|{imports.colors.PURPLE}Purple{imports.colors.END}|{imports.colors.BLUE}Blue{imports.colors.END}]",
            f"team\nlab environments to be monitored for malicious activity.")
    
    print(f"\n{imports.emoji.emojize(':disguised_face:')} Red Ranger is watching...\n")

    print(f"{imports.colors.GREY}https://github.com/gregohmyeggo/Tripwire.py{imports.colors.END}\n")

    print(f"{imports.colors.CYAN}Usage: tripwire.py -h{imports.colors.END}\n")

    print(f"To every {imports.colors.YELLOW}Action{imports.colors.END} there is always an equal {imports.colors.YELLOW}Reaction{imports.colors.END}. -Sir Isaac Newton\n")


## Generates the log timestamp
def log():
    log = f"{imports.colors.DEBUG}[{imports.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]{imports.colors.END}"
    return log

def tallyRules():
    print(f"{imports.colors.GREY}Enabled Rules: {len(getRules(True))}{imports.colors.END}")


## title(True) to return lab status in title screen.
def title(*argv):
    clear_console()
    title = '''
           |*-*-*-*-*-*-*|
  _____    |             |         
 |_   _| _(_)_ ____ __ _(_)_ _ ___ 
   | || '_| | '_ \ V  V / | '_/ -_)
   |_||_| |_| .__/\_/\_/|_|_| \___|
            |_|ython                                      
    '''
    print(f"{imports.colors.RED}{title}{imports.colors.END}")

    if vmrest_status() == True:
        print(f"VMRest: {imports.colors.GREEN}Online{imports.colors.END}")
    else:
        print(f"VMRest: {imports.colors.RED}Offline{imports.colors.END}")


    c2 = []
    if data['C2']['Sliver'] == True:
        c2.append('Sliver')
    if data['C2']['Covenant'] == True:
        c2.append('Covenant')
    print(f"C2 Logging: {c2}")
    # print(f"Enabled Rules: {len(imports.functions.getRules(True))}")        
    barbed_wire()


## Checks the status of VMWare Workstation REST API
def vmrest_status():
    try:
        r = imports.requests.get(f'{imports.variables.url}/vms', headers=imports.variables.headers)
        if r.status_code == 200:
            return True
    except:
        return False


## Main monitoring loop
def red_ranger(caseID, version):

    # print(f"DEBUG: {caseID}")

    tripped = []                           # Tracks alert UUIDs per session

    #DEBUG
    # print(len(getAlertsFromCase(caseID)))

    
    if len(getAlertsFromCase(caseID)) > 0:
        for alert in getAlertsFromCase(caseID):     # Updates tripped with the previous session's alert ids.
            if alert['id'] not in tripped:
                tripped.append(alert['id'])
    
        print(f"{imports.colors.GREY}Previously Tripped Alerts: {len(getAlertsFromCase(caseID))}{imports.colors.END}")

    count = 0           # Tally of alert UUIDs per session
    command_ids = []    # Tracks Sliver command _id values to prevent reuse
    dt = (imports.datetime.utcnow().strftime(f"%Y-%m-%dT%H:%M:%S.%f")[:-3]) + 'Z'      # Prevents historical Sliver logs from appearing
    # print(f"{imports.colors.YELLOW}[DEBUG] {dt}{imports.colors.END}")                # [DEBUG]
    
    case = findCase(caseID)

    if case['status'] != 'in-progress':
        # Updates the case to "in-progress"; allows for alerts to be "acknowledged" and then "closed"
        updateCase(caseID, "in-progress")

    barbed_wire()

    print(f"\n{imports.emoji.emojize(':disguised_face:')} {imports.colors.RED}Red Ranger{imports.colors.END} is watching...\n")

    # Main Loop; continues until KeyboardInterrupt
    try:
        # Loops every 5 seconds
        while True:     
        
            # Elasticsearch Security Alerts
            r = imports.requests.get(imports.variables.elasticsearch_url, headers=imports.variables.elk_headers, verify=False)
            hits = r.json()

            for hit in hits['hits']['hits']:

                # !!!
                # TBD: Redisign the logging options for each log type?
                # Pass in the full 'hit' and filter down per log.

                # ELK Values; used for attaching the alert to the case.
                rule_name = hit['_source']['kibana.alert.rule.name']
                rule_id = hit['_source']['kibana.alert.rule.execution.uuid']
                _id = hit['_id']
                _index = hit['_index']


                timestamp = hit['_source']['@timestamp']
                host = hit['_source']['agent']['hostname']
                status = hit['_source']['kibana.alert.workflow_status']
                severity = hit['_source']['kibana.alert.severity']

                if status == 'open':
                    if _id not in tripped:
                        # print(f"{imports.colors.YELLOW}[DEBUG] {hit}{imports.colors.END}")        # [DEBUG]

                        if severity == 'critical':
                            print(f"{imports.emoji.emojize(':police_car_light:')} Critical")
                        if severity == 'high':
                            print(f"{imports.emoji.emojize(':police_car_light:')} High")
                        if severity == 'medium':
                            print(f"{imports.emoji.emojize(':police_car_light:')} Medium")
                        if severity == 'low':
                            print(f"{imports.emoji.emojize(':police_car_light:')} Low")

                        # Update output with log-specific alerts: Defender, Sysmon, etc.

                        base_alert(hit, rule_name, _id, timestamp, host)
                        
                        if getAlertsFromCase(caseID):
                            for alert in getAlertsFromCase(caseID):
                                if _id != alert['id']:
                                    attachAlerts(caseID, _id, _index, rule_id, rule_name)
                        else:
                            attachAlerts(caseID, _id, _index, rule_id, rule_name)
                        

                        tripped.append(_id)
                        count+=1

            imports.time.sleep(2)


            #-*-*-*-*-*-*-*-*-*-*-*-#
            #                       #
            #   C2 Framework Logs   #
            #                       #
            #-*-*-*-*-*-*-*-*-*-*-*-#

            # Each C2 framework will have different logging capabilities; these are defined below.
            # Configure environment.yml ["C2"][(framework)]: True|False

            # Sliver: getSliver()
            if data["C2"]["Sliver"] == True:
                cmd_id = getSliver(command_ids, caseID, dt)
                if cmd_id:
                    command_ids.append(cmd_id)

                imports.time.sleep(2)

            # Covenant
            # TBD: getCovenant()

    # Will run until the user stops the script.
    except KeyboardInterrupt:
        ans = input("Close case? (y|n): ")
        if ans.upper() == 'Y':
            closeCase(caseID)
            print(f"\n[*] Closing {imports.colors.CYAN}{case['title']}{imports.colors.END}")
            print(f'\n{log()} Total Alerts: {count}\n')
            quit()
        else:
            print(f'\n{log()} Total Alerts: {count}\n')


## Starts virtual machines
def startVM(virtual_machine_ids, state):
    for ids in virtual_machine_ids:
        _id = ids['id']
        r = imports.requests.put(f'{imports.variables.url}/vms/{_id}/power', headers=imports.variables.headers, data=state)
    
    imports.time.sleep(5.0)


## Stops running virtual machines
def stopVM(vmx):
    # vmx = "\"G:\\Tripwire\\VirtualMachines\\win10\\win10.vmx\""
    imports.subprocess.run(f"C:\\Program Files (x86)\\VMware\\VMware Workstation\\vmrun.exe -T ws stop {vmx}", capture_output=True)
    print(f"{imports.colors.DEBUG}[i] Stopped {vmx}{imports.colors.END}")


## Modifies the case "status"; used to set the case to "in-progress"
# - Will also update the case with the list of enabled rules.
# - Will also update the case with a "challenge" technique.
def updateCase(caseID, status):

    cases = getCases()
    for case in cases:
        if caseID in case['id']:
            version = case['version']

    # https://www.elastic.co/guide/en/kibana/master/cases-api-update.html#_request_body_5
    data = {
        "cases": [
            { 
            "id": caseID,
            "version": version,
            "status": status,
            }
        ]
    }

    url = f"{imports.variables.kibana_url}/cases"
    r = imports.requests.patch(url, headers=imports.variables.elk_headers, data=imports.json.dumps(data))

    # Adds a string-list of currently enabled rules to the case
    # Included in the updateCase() function to prevent any duplicated comments.
    sRules = ("#### **Enabled Rules:**\n"+('\n'.join(map(str, getRules(True)))))
    addComment(caseID, sRules)

    print(f"\n[*] \"We're getting things ready\"")

    # Updates the case with a "challenge" technique
    getTechnique(caseID)


## Starts VMware Rest API
def vmrest():
    vmrest = '"C:\\Program Files (x86)\\VMware\\VMware Workstation\\vmrest.exe"'
    imports.os.startfile(f"{vmrest}")
    return True