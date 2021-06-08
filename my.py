import falco
import requests
import os

def sendHTTPRequest(podName):
    # port = "30009"
    # url = "10.0.2.15"
    url = "phoenix-operator.phoenix-operator.svc"
    port = "8088"
    request = "http://{}:{}/kill?pod={}".format(url, port, podName)

    try:
        r = requests.get(request)
        print("Request sent: " + str(r.url))
        print("Status code: " + str(r.status_code))
        print("Response: " + str(r.text))
    except:
        print("Error sending request")    


client = falco.Client(endpoint="unix:///var/run/falco/falco.sock", 
        client_crt="/tmp/client.crt", 
        client_key="/tmp/client.key", 
        ca_root="/tmp/ca.crt")
        #client_crt="/tmp/client.crt", 
        #client_key="/tmp/client.key", 
        #ca_root="/tmp/ca.crt")

# client = falco.Client(endpoint="0.0.0.0:5060", client_crt="/tmp/client.crt", client_key="/tmp/client.key", ca_root="/tmp/ca.crt")

for event in client.sub():
    print("#"*5 + " New event " + "#"*5)
    print("Time: " + str(event.time) )
    print("Host: " + str(event.hostname) )
    print("Priority: " + str(event.priority) )
    print("Source: " + str(event.source) )
    print("Rule: " + str(event.rule) )
    print("Output: " + str(event.output)[:100] + "...")
    
    pod =  str(event.output_fields['k8s.pod.name'])
    print("Pod: " + pod)
   
    print("Fields:")
    for field in event.output_fields:
        print("\t{}: {}".format(field, event.output_fields[field]))

    if pod != "<NA>" and str(event.rule) == "Read sensitive file untrusted":
        sendHTTPRequest(event.output_fields['k8s.pod.name'])
    else:
        print("Event not contained podname")
    # print("Fields: " + str(event.output_fields) 
