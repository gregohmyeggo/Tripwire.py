import imports 

## ELK IP
elk_ip = "192.168.86.32"

## Loads in the .yaml configuration file. Placeholder for future updates.
stream = open('environment.yml', 'r')
data = imports.yaml.safe_load(stream)
# vmids = []

## Authenticates the VMware REST API
auth = imports.base64.b64encode(str.encode(data['VMWARE_API']['USERNAME']+":"+data['VMWARE_API']['PASSWORD'])).decode('utf-8')

## Base VMware REST API URL
url = "http://127.0.0.1:8697/api"
headers = {'Content-Type': 'application/vnd.vmware.vmw.rest-v1+json', 'Accept': 'application/vnd.vmware.vmw.rest-v1+json','Authorization': 'Basic {0}'.format(auth)}

## Directory of virtual machines
vm_path = data['ENVIRONMENT']['VM_PATH']

## ELK
# alerts_index = ".internal.alerts-security.alerts-default-000003"
alerts_index = ".internal.alerts-security.alerts-default-000001"
elasticsearch_url = f"https://{elk_ip}:9200/{alerts_index}/_search"
kibana_url = f"http://{elk_ip}:5601/api"

filebeat_index = ".ds-filebeat-8.6.2-2023.05.25-000004"
filebeat_url = f"https://{elk_ip}:9200/{filebeat_index}/_search"
fb_headers = {f'Authorization': f'{data["ELK_API"]["KEY"]}'}

elk_headers = {'kbn-xsrf': 'true','content-type': 'application/json','Authorization': f'{data["ELK_API"]["KEY"]}'}