import json
import os
import sys
from flask import Flask, request
import requests
import logging
import jwt
import IPy

# variables
NOTIFICATION_FIREBASE_KEY = os.getenv("NOTIFICATION_FIREBASE_KEY", None)
AUTH_APP_URL = os.getenv("AUTH_APP_URL", None)
AUTH_APP_CLIENT_ID = os.getenv("AUTH_APP_CLIENT_ID", None)
AUTH_APP_CLIENT_SECRET = os.getenv("AUTH_APP_CLIENT_SECRET", None)
AUTH_APP_AUDIENCE = os.getenv("AUTH_APP_AUDIENCE", None)

DEBUG = int(os.getenv("DEBUG", 0))

# initialization
version = "1.0-4"
app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.WARNING)
print "Running API Server v"+version

# check if an IP is private
def is_private_ip(ip):
    ip = IPy.IP(ip)
    if ip.iptype() in ["PRIVATE", "LOOPBACK"]: 
        return True
    return False
    
# auth api (on_register_hook) - implement the oauth "Resource Owner Password Grant" flow
@app.route("/api/v1/auth/on_register_hook", methods=['POST', 'GET'])
def auth_on_register_hook():
    # get the request
    payload = request.get_json(force=True)
    response_headers = {
        "cache-control": "max-age=300"
    }
    # ensure the api is configured
    if AUTH_APP_AUDIENCE is None or AUTH_APP_CLIENT_ID is None or AUTH_APP_CLIENT_SECRET is None or AUTH_APP_URL is None:
        error = "api not configured"
        print "ERROR: "+error
        return (json.dumps({"result": {"error": error}}), 500)
    # sanity checks
    if not is_private_ip(request.remote_addr):
        error = 'not allowed to call this api from '+request.remote_addr
        print "ERROR: "+error
        return (json.dumps({'result': {'error': error}}), 500)
    if "password" not in payload or "username" not in payload: 
        error = 'username/password not provided'
        print "ERROR: "+error
        return (json.dumps({'result': {'error': error}}), 500)
    log_prefix = "[AUTH]["+payload["username"]+"] "
    # prepare the oauth request
    request_headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "grant_type": "password",
        "username": payload["username"],
        "password": payload["password"],
        "audience": AUTH_APP_AUDIENCE,
        "client_id": AUTH_APP_CLIENT_ID,
        "client_secret": AUTH_APP_CLIENT_SECRET,
    }
    # send the oauth request
    if DEBUG:
        print log_prefix+"IAM request: "+json.dumps(data)
    try:
        response = requests.post(AUTH_APP_URL, headers=request_headers, data=data)
    except Exception, e:
        print log_prefix+"ERROR: "+str(e)
        return (json.dumps({'result': {'error': str(e)}}), 500)
    if DEBUG:
        print log_prefix+"IAM response: "+response.text
    # parse the response
    try:
        result = json.loads(response.text)
        # successful authentication
        if "access_token" in result:
            print log_prefix+"OK"
            token = jwt.decode(result["access_token"], "", verify=False)
            # grant access and set ACLs
            response_text = {
                "result": "ok",
                "publish_acl": [
                    {
                        "pattern": "egeoffrey/+/"+payload["username"]+"/#"
                    }
                ],
                "subscribe_acl": [
                    {
                        "pattern": "egeoffrey/+/"+payload["username"]+"/#"
                    }
                ]
            }
            return (json.dumps(response_text), 200, response_headers)
        # failed authentication
        else:
            print log_prefix+"ERROR: "+result["error_description"]
            return (json.dumps({'result': {'error': result["error_description"]}}), 200, response_headers)
    except Exception, e:
        print log_prefix+"ERROR: "+str(e)
        return (json.dumps({'result': {'error': str(e)}}), 500)

# notify api
@app.route("/api/v1/notify", methods=['POST', 'GET'])
def notify():
    if NOTIFICATION_FIREBASE_KEY is None:
        return "api not configured"
    firebase_url = "https://fcm.googleapis.com/fcm/send"
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
    log_prefix = "["+notification["gateway_hostname"]+"]["+notification["house_id"]+"]["+notification["severity"].upper()+"] "
    if DEBUG:
        print log_prefix+"received notification: "+str(notification)
    # route the notification through FCM
    headers = {
        "Content-Type": "application/json",
        "Authorization": "key="+NOTIFICATION_FIREBASE_KEY
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
        if DEBUG:
            print log_prefix+"FCM request: "+json.dumps(message)
        response = requests.post(firebase_url, headers=headers, data=json.dumps(message))
        # check for errors
        if response.status_code != 200:
            print log_prefix+"ERROR: "+str(response.text)
            failure = failure+1
            results[device] = str(response.text)
            continue
        try:
            result = json.loads(response.text)
        except Exception, e:
            print log_prefix+"ERROR: "+str(e)
            failure = failure+1
            results[device] = str(e)
            continue
        if result["failure"] > 0:
            print log_prefix+"ERROR: "+str(result["results"][0]["error"])
            failure = failure+1
            results[device] = str(result["results"][0]["error"])
            continue
        # sent successfully
        success = success+1
        results[device] = "OK"
        if DEBUG:
            print log_prefix+"FCM response: "+str(result)
    # print summary information
    print log_prefix+"notified "+str(success)+"/"+str(len(notification["devices"]))+" devices"
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
    # run the api server
    app.run(host= '0.0.0.0', debug=DEBUG, threaded=True)
