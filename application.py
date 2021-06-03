import os
import boto3
from flask import Flask, render_template, url_for, flash, redirect, request,session
from botocore.exceptions import ClientError
import hmac
import hashlib
import base64
from forms import LoginForm, RegistrationForm, VerificationForm
from werkzeug.utils import secure_filename


application = Flask(__name__)
application.secret_key = "random"

USER_POOL_ID = "us-east-2_nagpiCoBg"
CLIENT_ID = "4j0en13derud9o0ft5lt0ennp0"
CLIENT_SECRET = "10gt437u94l7di3s3qik38i8g1io7kkpp21s0si2fesogpjl8n5r"

client = boto3.client('cognito-idp', region_name = 'us-east-2')

def get_secret_hash(username):
    msg = username + CLIENT_ID
    dig = hmac.new(str(CLIENT_SECRET).encode('utf-8'),
        msg = str(msg).encode('utf-8'), digestmod=hashlib.sha256).digest()
    d2 = base64.b64encode(dig).decode()
    return d2

def cognito_sign_up(email, username, password, given_name, family_name, phone_no, filename):
    try:
        response = client.sign_up(
            ClientId=CLIENT_ID,
            SecretHash=get_secret_hash(username),
            Username=username,
            Password=password,
            UserAttributes=[
                {
                    'Name': "given_name",
                    'Value': given_name
                },
                {
                    'Name': "family_name",
                    'Value': family_name
                },
                {
                    'Name': 'phone_number',
                    'Value': phone_no
                },
                {
                    'Name': 'email',
                    'Value': email
                },
                {
                    'Name': 'picture',
                    'Value': filename
                }
            ],
            ValidationData=[
                {
                    'Name': "email",
                    'Value': email
                },
                {
                    'Name': "username",
                    'Value': username
                }
            ]
        )
    except Exception as e:
        return e
    return ''

def cognito_confirm_sign_up(username, code):
    try:
        response = client.confirm_sign_up(
            ClientId=CLIENT_ID,
            SecretHash=get_secret_hash(username),
            Username=username,
            ConfirmationCode=code,
            ForceAliasCreation=False,
        )
    except Exception as e:
        return e

    return ''


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
        return {}
    return response


def cognito_get_user(accesstoken):
    try:
        response = client.get_user(
            AccessToken=accesstoken
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
        session.pop(key, None)

def isLoggedIn():
    return session != {}

@application.route("/", methods = ['GET', 'POST'])
@application.route("/register", methods = ['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.Email_ID.data
        username = form.user_name.data
        passowod = form.Password.data
        given_name = form.given_name.data
        family_name = form.family_name.data
        phone_no = form.phone_no.data
        picture = form.profile_img.data
        filename = secure_filename(picture.filename)
        try_register =cognito_sign_up(email, username, passowod, given_name, family_name, phone_no, filename)
        if try_register == '': # no exception
            print("Hi I am a new user.")
            flash("User Registered Successfully..!!", 'success')
            return redirect(url_for('verification', username= username))
        else:
            print(try_register)
            flash(str(try_register), 'danger')
    return render_template("register.html", form= form)


@application.route("/verification/<username>", methods=["GET", "POST"])
def verification(username):
    form = VerificationForm()
    if form.validate_on_submit():
        code = form.verification_code.data
        tryverifying = cognito_confirm_sign_up(username, code)

        if tryverifying == '':  # verified successfully
            print("Verified Successfully")
            flash("User Verified Successfully..!!", 'success')
            return redirect('/login')

        else:  # not verified
            print(tryverifying)
            flash(str(tryverifying), 'danger')
            return render_template("verification.html",username=username, form= form)

    return render_template("verification.html", username=username, form=form)


@application.route("/login", methods =['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.user_name.data
        password = form.Password.data
        print("Password is:",password)
        tryfindinguser = initiate_auth(username, password)
        if tryfindinguser == {}:
            print("Login Failed")
            flash("Login Failed", 'danger')
            return render_template("login.html", form= form)
        else:
            accesstoken = tryfindinguser['AuthenticationResult']['AccessToken']
            User_Details = cognito_get_user(accesstoken)
            flash("Logged in Successfully", 'success')
            return render_template("Home.html", userdetails = User_Details)
    return render_template("login.html", form = form)


if __name__ == "__main__":
    application.run(debug=True)
