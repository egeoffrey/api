FROM python:2.7-alpine
EXPOSE 5000
RUN apk update && apk add musl-dev openssl-dev gcc libffi-dev && rm -rf /var/cache/apk/*
RUN pip install flask requests IPy pyjwt paho-mqtt cryptography
COPY . $WORKDIR
CMD [ "python", "api.py" ]
