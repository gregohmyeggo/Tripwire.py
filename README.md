# Tripwire.py
Tripwire is a virtual machine orchestration script, designed to supplement red|purple|blue team lab environments.

https://medium.com/@hacksplaining/a-new-tripwire-but-in-python-96a5f5b33a3f

### Usage
```
usage: tripwire.py [-h] [-s] [-x] [-l] [-i]

options:
  -h, --help         show this help message and exit
  -s, --start        Starts virtual machines
  -x, --stop         Starts virtual machines
  -l, --launch       Red Ranger will start monitoring for tripped alerts
  -i, --information  Additional Information
```
`tripwire.py -s` will also start vmrest.exe in the default installation directory: `C:\Program Files (x86)\VMware\VMware Workstation\vmrest.exe`. If located in a different directory, update vmrest() in functions.py.

### Requirements
- Virtual machine running Elasticsearch and Kibana
  - https://www.elastic.co/guide/en/elasticsearch/reference/current/install-elasticsearch.html
  - https://www.elastic.co/guide/en/kibana/current/install.html
    - Add `xpack.encryptedSavedObjects.encryptionKey: "<32 character string>"` to the `kibana.yml`
  - API key with appropriate permissions to review logs, create and modify cases and alerts.
    - `Stack Management > Security: API keys > Create API key`
- Lab VMs running Winlogbeats to ship event logs to Kibana

Be sure to modify `environment.yml` with the required information.
  - ENVIRONMENT, VM_PATH: Directory of your Virtual Machines; this is used for starting and stopping the virtual machines.
  - VMWARE_API, USERNAME|PASSOWRD: Username and Password configured per `vmrest.exe -C`
    - https://docs.vmware.com/en/VMware-Workstation-Pro/17/com.vmware.ws.using.doc/GUID-C3361DF5-A4C1-432E-850C-8F60D83E5E2B.html
  - ELK_API, KEY: Create an API key in ELK; Stack Management > Security: API keys > Create API key.
  - C2, Sliver|Covenant: These can be set to True or False depending on their use from your attacking vm. The script currently has a function to populate Sliver commands to the console and security cases (requires Filebeats to be configured on your attacking vm).

```yaml
ENVIRONMENT:
  VM_PATH: '<change-me>'

VMWARE_API:
  USERNAME: '<change-me>'
  PASSWORD: '<change-me>'

ELK_API:
  KEY: 'ApiKey <change-me>'

C2:
  Sliver: False
  Covenant: False
```
