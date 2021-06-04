# neuroflow-restful-api

## About
REST API backend for simple mood webapp. Uses Flask and SQLAlchemy. Containerization coming soon.

## Instructions (linux)
Install dependencies:
```
pip3 install -r requirements.txt
```
Initialize database if necessary:
```
python3 db.py
```
Run app:
```
python3 app.py
```

## API
You may send GET and POST http requests as you see fit (python requests, postman etc.). Here's how to login and get started:

```
Request

GET http://localhost:5000/login
Authorization: basic admin:admin
content-type application/json

Response

HTTP/1.0 200 OK
Content-Type: application/json
Content-Length: 191
Server: Werkzeug/2.0.1 Python/3.7.3
Date: Fri, 04 Jun 2021 19:43:23 GMT

{
    "token": <token here>
}
```

For actions requiring authentication, add X-Access-Token: <token> to your request header:
```
POST http://localhost:5000/mood HTTP/1.1
X-Access-Token: <token here>
content-type: application/json

{
    "value": "Here is where you put a mood value."
}
```

## Project Layout

```
neuroflow-restful-api/
    api/
        model/
            __init__.py
            mood.py
            user.py
        routes/
            login.py
            mood.py
            user.py
    test/
        __init__.py
        unittests.py
    .gitignore
    app.py
    db.py
    config.py
    requirements.txt
```

## Branches
Current branches:
### main
Latest version of API
### rudimentary
Earliest version of the API that meets the requirements for mood endpoints. All routes, classes, etc. contained in one file app.py.
### new-layout
On par with rudimentary branch, but uses the new project file/folder structure

