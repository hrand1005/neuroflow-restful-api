FROM python:3.9.1
ADD . /flask-app
WORKDIR /flask-app
RUN pip install -r requirements.txt
