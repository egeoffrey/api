import json
import os
import sys
from flask import Flask, request
import requests

# constants and variables
version = "1.0-2"
api_version = 1
debug = int(os.getenv("DEBUG", 0))
config_file = "config/config.json"
app = Flask(__name__)
config = None
url = "https://fcm.googleapis.com/fcm/send"

def print_log(notification, message):
    print "["+notification["gateway_hostname"]+"]["+notification["house_id"]+"]["+notification["severity"].upper()+"] "+str(message)

# notify api
@app.route("/api/v"+str(api_version)+"/notify", methods=['POST', 'GET'])
def notify():
    # parse the request json payload
    notification = request.get_json(force=True)
    # ensure mandatory settings are provided
    for setting in ["gateway_hostname", "house_id", "house_name", "severity", "message", "devices"]:
        if setting not in notification:
            return "Mandatory parameter '"+setting+"' not provided"
    if not isinstance(notification["devices"], list):
        return "Parameter 'devices' must be an array"
    if len(notification["devices"]) == 0:
        return "Parameter 'devices' must contain at least one value"
    if debug:
        print_log(notification, "received notification: "+str(notification))
    # route the notification through FCM
    headers = {
        "Content-Type": "application/json",
        "Authorization": "key="+config["fcm_server_key"]
    }
    success = 0
    failure = 0
    results = {}
    # for each device to notify
    for device in notification["devices"]:
        # prepare the message
        message = {}
        data = notification.copy()
        data["type"] = "notification"
        data["title"] = data["house_name"]
        data["body"] = data["message"]
        del data["message"]
        del data["devices"]
        message["to"] = device
        message["data"] = data
        # send the request to Firebase
        if debug:
            print_log(notification, "FCM request: "+json.dumps(message))
        response = requests.post(url, headers=headers, data=json.dumps(message))
        # check for errors
        if response.status_code != 200:
            print_log(notification, "ERROR: "+str(response.text))
            failure = failure+1
            results[device] = str(response.text)
            continue
        try:
            result = json.loads(response.text)
        except Exception, e:
            print_log(notification, "ERROR: "+str(e))
            failure = failure+1
            results[device] = str(e)
            continue
        if result["failure"] > 0:
            print_log(notification, "ERROR: "+str(result["results"][0]["error"]))
            failure = failure+1
            results[device] = str(result["results"][0]["error"])
            continue
        # sent successfully
        success = success+1
        results[device] = "OK"
        if debug:
            print_log(notification, "FCM response: "+str(result))
    # print summary information
    print_log(notification, "notified "+str(success)+"/"+str(len(notification["devices"]))+" devices")
    # return the result
    output = {
        "success": success,
        "failure": failure,
        "results": results
    }
    return json.dumps(output)
    
# catch all route
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    return "Invalid API method "+str(path)+"<br><br><i>API Server v"+version+"</i>"

# main
if __name__ == '__main__':
    # load the configuration file
    if not os.path.isfile(config_file):
        print "configuration file not found at "+config_file
        sys.exit(1)
    try:
        with open(config_file) as json_file:
            config = json.load(json_file)
    except Exception, e: 
        print "unable to parse configuration file "+config_file+": "+str(e)
        sys.exit(1)
    for setting in ["fcm_server_key"]:
        if setting not in config:
            print "setting "+setting+" not found in configuration file"
            sys.exit(1)
    # run the api server
    app.run(host= '0.0.0.0', debug=debug)
