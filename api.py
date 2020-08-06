import json
import os
import sys
from flask import Flask, request
import requests
import logging
import jwt
import IPy
import time
import struct
import paho.mqtt.client as mqtt

# Firebase key for notifications
NOTIFICATION_FIREBASE_KEY = os.getenv("NOTIFICATION_FIREBASE_KEY", None)
# oauth token endpoint for authentication requests
AUTH_APP_URL = os.getenv("AUTH_APP_URL", None)
# authentication app client id
AUTH_APP_CLIENT_ID = os.getenv("AUTH_APP_CLIENT_ID", None)
# authentication app client secret
AUTH_APP_CLIENT_SECRET = os.getenv("AUTH_APP_CLIENT_SECRET", None)
# authentication app audience
AUTH_APP_AUDIENCE = os.getenv("AUTH_APP_AUDIENCE", None)
# authentication app public key for jwt signature validation
AUTH_APP_PUBLIC_KEY = os.getenv("AUTH_APP_PUBLIC_KEY", None)
if AUTH_APP_PUBLIC_KEY is not None:
    AUTH_APP_PUBLIC_KEY = AUTH_APP_PUBLIC_KEY.replace("\\n","\n")
# authentication app namespace for retrieving additional information from the jwt token
AUTH_APP_NAMESPACE = "https://api.egeoffrey.com/"
# Cloud Gateway hostname
GATEWAY_HOSTNAME = os.getenv("GATEWAY_HOSTNAME", None)
# Cloud Gateway port
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", 0))

# initialization
version = "1.0-5"
app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.WARNING)

#####################################
# COMMON FUNCTIONS

# check if an IP is private
def is_private_ip(ip):
    ip = IPy.IP(ip)
    if ip.iptype() in ["PRIVATE", "LOOPBACK"]: 
        return True
    return False
    
# return a random integer
def get_random():
    return struct.unpack("<L", os.urandom(4))[0]

# print a log message
def print_log(log_template, severity, message):
    log_template["timestamp"] = int(time.time())
    log_template["severity"] = severity
    log_template["message"] = message
    print json.dumps(log_template)   
    
# print and return an api error
def log_error(log_template, message):
    print_log(log_template, "error", message)
    return (json.dumps({"result": {"error": message}}), 500)
    
# log a warning message
def log_warning(log_template, message=""):
    print_log(log_template, "warning", message)
    
# log a debug message if DEBUG is on
def log_debug(log_template, message=""):
    debug = int(os.getenv("DEBUG"+log_template["api"].upper().replace("/","_"), 0))
    if debug: 
        print_log(log_template, "debug", message)
        
# log an info message
def log_info(log_template, message=""):
    print_log(log_template, "info", message)
    
# log a success message
def log_success(log_template, message=""):
    print_log(log_template, "success", message)

# return the log template
def get_log_template():
    return {
        "api": request.path,
        "request_id": get_random()
    }
    
#####################################
# APIs

# handle requests from Google Assistant for a chatbot connected to the cloud gateway
@app.route("/api/v1/chatbot/google_assistant", methods=['POST', 'GET'])
def chatbot_google_assistant():
    log_template = get_log_template()
    if AUTH_APP_NAMESPACE is None or AUTH_APP_PUBLIC_KEY is None or AUTH_APP_AUDIENCE is None or GATEWAY_HOSTNAME is None or GATEWAY_PORT == 0:
        return log_error(log_template, "API not configured")
    # get the request
    payload = request.get_json(force=True)
    if "intent" not in payload or "query" not in payload["intent"]:
        return log_error(log_template, "invalid request: "+str(payload))
    # get the access token passed by the Google Actions service
    if "Authorization" not in request.headers:
        return log_error(log_template, "access token is missing")
    access_token = request.headers["Authorization"].replace("Bearer ","")
    # validate the access token
    try:
        token = jwt.decode(access_token, AUTH_APP_PUBLIC_KEY, audience=AUTH_APP_AUDIENCE)
    except Exception, e:
        return log_error(log_template, str(e))
    if AUTH_APP_NAMESPACE+"email" not in token:
        return log_error(log_template, "invalid token format, email is missing")
    username = token[AUTH_APP_NAMESPACE+"email"]
    password = access_token
    userdata = {}
    log_template["username"] = username
    # setup connection to the Cloud Gateway
    mqtt_client = mqtt.Client(userdata=userdata)
    request_id = get_random()
    # configure on_connect()
    def on_connect(mqtt_client, userdata, flags, rc):
        if rc == 0:
            try:
                log_debug(log_template, "Connected to the MQTT gateway ("+str(rc)+")")
                # subscribe to the topic where we expect the chatbot to reply
                subscribe_topic = "egeoffrey/v1/"+username+"/controller/chatbot/system/api_"+str(request_id)+"/ASK/null"
                log_debug(log_template, "Subscribing to the MQTT topic "+subscribe_topic)
                mqtt_client.subscribe(subscribe_topic)
                # send the request to the chatbot
                message = {
                    "request_id": request_id,
                    "data":{
                        "request": payload["intent"]["query"],
                        "accept": ["text"]
                    }
                }
                publish_topic = "egeoffrey/v1/"+username+"/system/api_"+str(request_id)+"/controller/chatbot/ASK/null"
                mqtt_client.publish(publish_topic, json.dumps(message))
                log_debug(log_template, "Published on topic "+publish_topic+": "+str(message))
                log_debug(log_template, "request: "+payload["intent"]["query"])
            except Exception,e:
                return log_error(log_template, "exception during on_connect(): "+str(e))
        else:
            return log_error(log_template, "unable to connect to the cloud gateway")   
    # configure on_message()
    def on_message(mqtt_client, userdata, msg):
        try:
            # get the response of the chatbot
            chatbot_response = json.loads(msg.payload)
            chatbot_response = chatbot_response["data"]["content"]
            log_debug(log_template, "response: "+chatbot_response)
            # format what to send back to Google
            response = {
                "session": {
                    "id": payload["session"]["id"],
                    "params": {}
                },
                "prompt": {
                    "override": False,
                    "firstSimple": {
                      "speech": chatbot_response
                    }
                }
            }
            userdata["response"] = response
        except Exception,e:
            return log_error(log_template, "exception during on_message(): "+str(e))
    # connect to the cloud gateway
    try: 
        log_debug(log_template, "Connecting to the gateway on "+GATEWAY_HOSTNAME+":"+str(GATEWAY_PORT))
        mqtt_client.username_pw_set(username, password=password)
        mqtt_client.connect(GATEWAY_HOSTNAME, GATEWAY_PORT, 10)
    except Exception,e:
        return log_error(log_template, "Unable to connect to the cloud gateway: "+str(e))
    # set callbacks
    mqtt_client.on_connect = on_connect
    mqtt_client.on_message = on_message
    try:
        # consume mqtt messages in background
        mqtt_client.loop_start()
        # keep running for a few seconds only
        for i in range(1,8):
            time.sleep(0.5)
            # check if we have been replied
            if "response" in userdata and userdata["response"] is not None:
                # disconnect from the gateway
                mqtt_client.loop_stop()
                mqtt_client.disconnect()
                # return the response
                log_success(log_template, "OK")
                return userdata["response"]
        # disconnect from the gateway
        mqtt_client.loop_stop()
        mqtt_client.disconnect()
        return log_error(log_template, "timeout occurred")
    except Exception,e:
        return log_error(log_template, "runtime error: "+str(e))
    
# auth api (on_register_hook) - implement the oauth "Resource Owner Password Grant" flow
@app.route("/api/v1/auth/on_register_hook", methods=['POST', 'GET'])
def auth_on_register_hook():
    log_template = get_log_template()
    # ensure the api is configured
    if AUTH_APP_AUDIENCE is None or AUTH_APP_PUBLIC_KEY is None or AUTH_APP_CLIENT_ID is None or AUTH_APP_CLIENT_SECRET is None or AUTH_APP_URL is None:
        return log_error(log_template, "API not configured")
    # get the request
    payload = request.get_json(force=True)
    # sanity checks, username and password expected in the request
    if "password" not in payload or "username" not in payload: 
        return log_error(log_template, "username/password not provided")
    log_template["username"] = payload["username"]
    access_token = None
    # if a password is provided, check it with the authentication service
    if len(payload["password"]) < 100:
        # prepare the oauth request
        data = {
            "grant_type": "password",
            "username": payload["username"],
            "password": payload["password"],
            "scope": "openid email profile",
            "client_id": AUTH_APP_CLIENT_ID,
            "client_secret": AUTH_APP_CLIENT_SECRET,
        }
        # send the oauth request
        try:
            log_debug(log_template, "IAM request: "+json.dumps(data))
            response = requests.post(AUTH_APP_URL, headers={"Content-Type": "application/x-www-form-urlencoded"}, data=data)
            log_debug(log_template, "IAM response: "+response.text)
        except Exception, e:
            return log_error(log_template, str(e))
        # parse the response
        try:
            result = json.loads(response.text)
            # extract the access token returned
            if "access_token" in result:
                access_token = result["access_token"]
            # failed authentication
            else:
                return log_error(log_template, result["error_description"])
        except Exception, e:
            return log_error(log_template, str(e))
    # the access token is already into the password field
    else:
        access_token = payload["password"]
    # validate the access token
    try:
        token = jwt.decode(access_token, AUTH_APP_PUBLIC_KEY, audience=AUTH_APP_AUDIENCE)
        # verify the token belongs to the right user
        valid_user = False
        if AUTH_APP_NAMESPACE+"email" in token and token[AUTH_APP_NAMESPACE+"email"] == payload["username"]:
            valid_user = True
        if AUTH_APP_NAMESPACE+"username" in token and token[AUTH_APP_NAMESPACE+"username"] == payload["username"]:
            valid_user = True
        if not valid_user:
            return log_error(log_template, "this token does not belong to the user "+payload["username"])
        # authentication successful
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
        log_success(log_template, "OK")
        return (json.dumps(response_text), 200, {"cache-control": "max-age=300"})
    except Exception, e:
        return log_error(log_template, str(e))

# notify api
@app.route("/api/v1/notify", methods=['POST', 'GET'])
def notify():
    log_template = get_log_template()
    if NOTIFICATION_FIREBASE_KEY is None:
        return log_error(log_template, "API not configured")
    firebase_url = "https://fcm.googleapis.com/fcm/send"
    # parse the request json payload
    notification = request.get_json(force=True)
    # ensure mandatory settings are provided
    for setting in ["gateway_hostname", "house_id", "house_name", "severity", "message", "devices"]:
        if setting not in notification:
            return log_error(log_template, "Mandatory parameter '"+setting+"' not provided")
    if not isinstance(notification["devices"], list):
        return log_error(log_template, "Parameter 'devices' must be an array")
    if len(notification["devices"]) == 0:
        return log_error(log_template, "Parameter 'devices' must contain at least one value")
    log_template["extra"] = {}
    log_template["extra"]["gateway_hostname"] = notification["gateway_hostname"]
    log_template["extra"]["house_id"] = notification["house_id"]
    log_debug(log_template, "received notification: "+str(notification))
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
        log_debug(log_template, "FCM request: "+json.dumps(message))
        response = requests.post(firebase_url, headers=headers, data=json.dumps(message))
        # check for errors
        if response.status_code != 200:
            log_warning(log_template, str(response.text))
            failure = failure+1
            results[device] = str(response.text)
            continue
        try:
            result = json.loads(response.text)
        except Exception, e:
            log_warning(log_template, str(e))
            failure = failure+1
            results[device] = str(e)
            continue
        if result["failure"] > 0:
            log_warning(log_template, str(result["results"][0]["error"]))
            failure = failure+1
            results[device] = str(result["results"][0]["error"])
            continue
        # sent successfully
        success = success+1
        results[device] = "OK"
        log_debug(log_template, "FCM response: "+str(result))
    # print summary information
    log_success(log_template, "notified "+str(success)+"/"+str(len(notification["devices"]))+" devices")
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
    app.run(host= '0.0.0.0', debug=False, threaded=True)
