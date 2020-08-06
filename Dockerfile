FROM python:2.7-alpine
EXPOSE 5000
RUN pip install flask requests IPy pyjwt paho-mqtt
COPY . $WORKDIR
CMD [ "python", "api.py" ]
