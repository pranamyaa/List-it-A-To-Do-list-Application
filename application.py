import boto3
import botocore.exceptions
import hmac
import hashlib
import base64
import json
import datetime

from flask import Flask, render_template, request, redirect, session, url_for
application = Flask(__name__)
application.secret_key = "random"

USER_POOL_ID = 'us-east-1_ML8n8zEda'
CLIENT_ID = '7e6fl49b57k982roaudequp1hi'
CLIENT_SECRET = '6373u966d5p8g89e2hil3b5qpg22nq2t50jkjr1n9m03c35kd0f'

client = boto3.client('cognito-idp', region_name='us-east-1')

dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
tasktable = dynamodb.Table('Task')
subtable = dynamodb.Table('Subtask')


def get_secret_hash(username):
    msg = username + CLIENT_ID
    dig = hmac.new(str(CLIENT_SECRET).encode('utf-8'), 
        msg = str(msg).encode('utf-8'), digestmod=hashlib.sha256).digest()
    d2 = base64.b64encode(dig).decode()
    return d2

# add user to the user pool
# return '' or exception message
def cognito_sign_up(email, username, password, name):
    try:
        response = client.sign_up(
            ClientId=CLIENT_ID,
            SecretHash=get_secret_hash(username),
            Username=username,
            Password=password, 
            UserAttributes=[
                {
                    'Name': "name",
                    'Value': name
                },
                {
                    'Name': "email",
                    'Value': email
                # },
                # {
                #     'Name': "custom:customfieldname",
                #     'Value': 'custom field value 3'
                }
            ],
            ValidationData=[
                {
                    'Name': "email",
                    'Value': email
                },
                {
                    'Name': "custom:username",
                    'Value': username
                }
            ]
        )
    except Exception as e:
        return e

    return ''

# check if user can provide a correct code sent
# return '' or exception message
def cognito_confirm_sign_up(username, code):
    try:
        response = client.confirm_sign_up(
            ClientId = CLIENT_ID,
            SecretHash = get_secret_hash(username),
            Username = username,
            ConfirmationCode = code,
            ForceAliasCreation = False,
        )
    except Exception as e:
        return e
    
    return ''

# get user info with username and password
# currently using this only to get access token
# return response or {}
def initiate_auth(username, password):
    try:
        response = client.admin_initiate_auth(
            UserPoolId=USER_POOL_ID,
            ClientId=CLIENT_ID,
            AuthFlow='ADMIN_NO_SRP_AUTH',
            AuthParameters={
                'USERNAME': username,
                'SECRET_HASH': get_secret_hash(username),
                'PASSWORD': password,
            },
            ClientMetadata={
                'username': username,
                'password': password,
            }
        )
    except Exception as e:
        print(e)
        return {}, e

    # response will look like:
    # {
    #     'ChallengeParameters': {},
    #     'AuthenticationResult':{
    #         'AccessToken': 'eyJraWQiOiJ5aXdpZHBsR2Z1S29PY3B2ckRXZXpsZmM0S longer than this',
    #         'ExpiresIn': 3600,
    #         'TokenType': 'Bearer',
    #         'RefreshToken': 'eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxn longer than this',
    #         'IdToken': 'eyJraWQiOiJJcThtb2Rrc09LdHVkSkJtMmtvR3hKblZnSHRiS longer than this'
    #     },
    #     'ResponseMetadata': {
    #         'RequestId': 'ab364442-3ec0-4163-9615-ff93b0deddcc',
    #         'HTTPStatusCode': 200,
    #         'HTTPHeaders': {
    #             'date': 'Wed, 02 Jun 2021 10:42:16 GMT',
    #             'content-type': 'application/x-amz-json-1.1',
    #             'content-length': '3791',
    #             'connection': 'keep-alive',
    #             'x-amzn-requestid': 'ab364442-3ec0-4163-9615-ff93b0deddcc'
    #         },
    #         'RetryAttempts': 0
    #     }
    # }
    return response, ''

# get user info with access token
# return response
def cognito_get_user(accesstoken):
    try:
        response = client.get_user(
            AccessToken = accesstoken
        )
    except Exception as e:
        print(e)
    
    # response will look like:
    # {
    #     'Username': 'user444',
    #     'UserAttributes':
    #         [
    #             {'Name': 'sub', 'Value': 'd0913529-85ef-4525-bc4f-5bb027de3a20'},
    #             {'Name': 'email_verified', 'Value': 'true'},
    #             {'Name': 'name', 'Value': 'name TEST 4'},
    #             {'Name': 'email', 'Value': 'icotpcatudnojrvuhw@niwghx.com'}
    #         ],
    #         'ResponseMetadata': {
    #             'RequestId': '6125862e-7c1f-46be-9e1a-f586bdaac8a2',
    #             'HTTPStatusCode': 200,
    #             'HTTPHeaders': {
    #                 'date': 'Wed, 02 Jun 2021 11:09:26 GMT',
    #                 'content-type': 'application/x-amz-json-1.1',
    #                 'content-length': '239',
    #                 'connection': 'keep-alive',
    #                 'x-amzn-requestid': '6125862e-7c1f-46be-9e1a-f586bdaac8a2'
    #             },
    #             'RetryAttempts': 0
    #         }
    # }
    return response

# empty session
def emptySession():
    for key in list(session.keys()):
        if key != 'csrftoken':
            session.pop(key, None)

def isLoggedIn():
    for key in list(session.keys()):
        if key != 'csrftoken':
            return True
    return False
    # return session != {}



# return current timestamp string
def getTimestamp():
    return str(datetime.datetime.now())

# Owner, TaskID, Title, Desc, Done, Fav
# returns None if task doesn't exist
def getTask(taskid, username):
    response = tasktable.get_item(Key={'TaskID': taskid, 'Owner': username})
    return response.get('Item')

# ParentTask, SubtaskID, Title, Desc, Due, Done, Image, Url
# returns None if subtask doesn't exist
def getSubtask(subtaskid, parenttask):
    response = subtable.get_item(Key={'SubtaskID': subtaskid, 'ParentTask': parenttask})
    return response.get('Item')

def addTask(title, desc, done, fav):
    response = tasktable.put_item(
       Item={
            'Owner': session['loggedinUsername'],
            'TaskID': getTimestamp(),
            'Title': title,
            'Desc': desc,
            'Done': done,
            'Fav': fav
        }
    )

def addSubtask(parenttask, title, desc, due, done, image, url):
    response = subtable.put_item(
       Item={
            'ParentTask': parenttask,
            'SubtaskID': getTimestamp(),
            'Title': title,
            'Desc': desc,
            'Due': due,
            'Done': done,
            'Image': image,
            'Url': url
        }
    )

# returns [] if empty
def getAllTasksByCurrentUser():
    scan_kwargs = {
        'FilterExpression': "#o = :u",
        "ExpressionAttributeValues": {
            ':u': session['loggedinUsername']
        },
        'ExpressionAttributeNames': {
            "#o": "Owner"
        }
    }
    response = tasktable.scan(**scan_kwargs)

    return response.get("Items")

# returns [] if empty
def getAllSubtasksByParent(parenttask):
    scan_kwargs = {
        'FilterExpression': "ParentTask = :p",
        "ExpressionAttributeValues": {
            ':p': parenttask
        }
    }
    response = subtable.scan(**scan_kwargs)

    return response.get("Items")



@application.route("/")
def root():
    return render_template("index.html")

@application.route("/register", methods=["GET", "POST"])
def register():
    if isLoggedIn():
        return redirect("/")
    else:
        if request.method == "POST":
            email = request.form["register-em"]
            username = request.form["register-un"]
            password = request.form["register-pw"]
            name = 'random name' ##
            tryregistering = cognito_sign_up(email, username, password, name)

            if tryregistering == '': # no exception
                return redirect(url_for('verification', username=request.form["register-un"]))

            else: # somethings wrong
                return render_template("register.html", exception=True, exceptionmsg=tryregistering)

            return redirect("/login")

        return render_template("register.html", exception=False)

@application.route("/verification/<username>", methods=["GET", "POST"])
def verification(username):
    if request.method == "POST":
        code = request.form["verification-code"]
        tryverifying = cognito_confirm_sign_up(username, code)

        if tryverifying == '': # verified successfully
            return redirect('/login')

        else: # not verified
            print(tryverifying)
            return render_template("verification.html", exception=True, exceptionmsg=tryverifying, username=username)
    
    return render_template("verification.html", exception=False, username=username)

@application.route("/login", methods=["GET", "POST"])
def login():
    if isLoggedIn():
        return redirect("/")
    else:
        if request.method == "POST":
            username = request.form['login-un']
            password = request.form['login-pw']
            tryfindinguser = initiate_auth(username, password)
            
            if tryfindinguser[0] == {}: # not found
                return render_template("login.html", showmessage=tryfindinguser[1])
            else: # user found
                accesstoken = tryfindinguser[0]['AuthenticationResult']['AccessToken']

                emptySession()
                # does not throw an error even if a desired attribute is not in the user attributes
                session['loggedinUsername'] = cognito_get_user(accesstoken)['Username']
                for a in cognito_get_user(accesstoken)['UserAttributes']:
                    if a['Name'] == 'email':
                        session['loggedinEmail'] = a['Value']
                    if a['Name'] == 'name':
                        session['loggedinName'] = a['Value']

                return redirect('/')

        return render_template("login.html", showmessage='')

@application.route("/logout", methods=["GET", "POST"])
def logout():
    emptySession()
    return redirect("/login")

@application.route("/tasks", methods=["GET", "POST"])
def tasks():
    # print(session['loggedinUsername'])
    # print(getAllTasksByCurrentUser())
    return render_template("tasks.html",
        tasks=getAllTasksByCurrentUser(),
        getAllSubtasksByParent=getAllSubtasksByParent)

if __name__ == "__main__":
    application.run(debug=True)
