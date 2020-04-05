FROM python:2.7-alpine
EXPOSE 5000
RUN pip install flask requests
COPY . $WORKDIR
CMD [ "python", "api.py" ]