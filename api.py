import json
import os
import sys
from flask import Flask, request
from pyfcm import FCMNotification

# constants and variables
version = "1.0-1"
api_version = 1
debug = int(os.getenv("DEBUG", 0))
config_file = "config/config.json"
app = Flask(__name__)
config = None
push_service = None

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
    # route the notification through FCM
    result = push_service.notify_multiple_devices(registration_ids=notification["devices"], message_title=notification["house_name"], message_body=notification
    ["message"])
    # log the result
    print "["+notification["gateway_hostname"]+"]["+notification["house_id"]+"]["+notification["severity"].upper()+"] notified "+str(result["success"])+"/"+str(len(notification["devices"]))+" devices"
    if debug:
        print notification["message"]+": "+str(result)
    # return the result
    return json.dumps(result)
    
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
    # initialize the push service
    push_service = FCMNotification(api_key=config["fcm_server_key"])
    # run the api server
    app.run(host= '0.0.0.0', debug=debug)
