import os
import sys
import getpass
import boto3
import configparser
import base64
import xml.etree.ElementTree as ET
import re
import pytz
import requests
import readline
import logging
import json
import traceback
import time
from datetime import datetime, timedelta
from pprint import pprint
from tzlocal import get_localzone
from datetime import datetime
from bs4 import BeautifulSoup
from os.path import expanduser
from urllib.parse import urlparse, urlunparse

# Variables

# Uncomment this line if you want to see the debug output
#logging.basicConfig(level=logging.DEBUG)

# Credentials file for AWS
# IMPORTANT: this is relative to your HOME directory (full path is determined by os.path.expanduser)
awsconfigfile="/.aws/credentials"

# Specific configuration file for launching instances
config_file="https://bitbucket.example.com/bitbucket/users/svejda/repos/scripts/raw/ec2.json"

# region: The default AWS region that this script will connect
# to for all API calls
region = 'eu-west-1'

# output format: The AWS CLI output format that will be configured in the
# saml profile (affects subsequent CLI calls)
outputformat = 'json'

# SSL certificate verification: Whether or not strict certificate
# verification is done, False should only be used for dev/test
sslverification = True

# idpentryurl: The initial url that starts the authentication process.
idpentryurl = 'https://sts.example.com/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices'

#######

def samladsv3(self):
    """Make connection to STS and get the authentication token"""
    try:
        # Get the federated credentials from the user
        print("[-] Get authentication token")
        print("Email:", end=' ')
        username = input()
        password = getpass.getpass()
        print('')

        # Initiate session handler
        session = requests.Session()

        # Programmatically get the SAML assertion
        # Opens the initial IdP url and follows all of the HTTP302 redirects, and
        # gets the resulting login page
        formresponse = session.get(idpentryurl, verify=sslverification)
        # Capture the idpauthformsubmiturl, which is the final url after all the 302s
        idpauthformsubmiturl = formresponse.url

        # Parse the response and extract all the necessary values
        # in order to build a dictionary of all of the form values the IdP expects
        formsoup = BeautifulSoup(formresponse.text, "html.parser")
        payload = {}

        for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
            name = inputtag.get('name','')
            value = inputtag.get('value','')
            if "user" in name.lower():
                #Make an educated guess that this is the right field for the username
                payload[name] = username
            elif "email" in name.lower():
                #Some IdPs also label the username field as 'email'
                payload[name] = username
            elif "pass" in name.lower():
                #Make an educated guess that this is the right field for the password
                payload[name] = password
            else:
                #Simply populate the parameter with the existing value (picks up hidden fields in the login form)
                payload[name] = value

        # Debug the parameter payload if needed
        # Use with caution since this will print sensitive output to the screen
        #print(payload)

        # Some IdPs don't explicitly set a form action, but if one is set we should
        # build the idpauthformsubmiturl by combining the scheme and hostname
        # from the entry url with the form action target
        # If the action tag doesn't exist, we just stick with the
        # idpauthformsubmiturl above
        for inputtag in formsoup.find_all(re.compile('(FORM|form)')):
            action = inputtag.get('action')
            loginid = inputtag.get('id')
            if (action and loginid == "loginForm"):
                parsedurl = urlparse(idpentryurl)
                idpauthformsubmiturl = parsedurl.scheme + "://" + parsedurl.netloc + action

        # Performs the submission of the IdP login form with the above post data
        response = session.post(
            idpauthformsubmiturl, data=payload, verify=sslverification)

        # Debug the response if needed
        #print(response.text)

        # Overwrite and delete the credential variables, just for safety
        username = '##############################################'
        password = '##############################################'
        del username
        del password

        # Decode the response and extract the SAML assertion
        soup = BeautifulSoup(response.text, "html.parser")
        assertion = ''

        # Look for the SAMLResponse attribute of the input tag (determined by
        # analyzing the debug print lines above)
        for inputtag in soup.find_all('input'):
            if(inputtag.get('name') == 'SAMLResponse'):
                #print(inputtag.get('value'))
                assertion = inputtag.get('value')

        # Better error handling is required for production use.
        if (assertion == ''):
            #TODO: Insert valid error checking/handling
            print('Response did not contain a valid SAML assertion')
            sys.exit(0)

        # Debug only
        #print(base64.b64decode(assertion))

        # Parse the returned assertion and extract the authorized roles
        awsroles = []
        root = ET.fromstring(base64.b64decode(assertion))
        for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
            if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
                for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                    awsroles.append(saml2attributevalue.text)

        # Note the format of the attribute value should be role_arn,principal_arn
        # but lots of blogs list it as principal_arn,role_arn so let's reverse
        # them if needed
        for awsrole in awsroles:
            chunks = awsrole.split(',')
            if'saml-provider' in chunks[0]:
                newawsrole = chunks[1] + ',' + chunks[0]
                index = awsroles.index(awsrole)
                awsroles.insert(index, newawsrole)
                awsroles.remove(awsrole)

        # If I have more than one role, ask the user which one they want,
        # otherwise just proceed
        print("")
        if len(awsroles) > 1:
            i = 0
            print("Please choose the role you would like to assume:")
            for awsrole in awsroles:
                print('[', i, ']: ', awsrole.split(',')[0])
                i += 1
            print("Selection: ", end=' ')
            selectedroleindex = input()

            # Basic sanity check of input
            if int(selectedroleindex) > (len(awsroles) - 1):
                print('You selected an invalid role index, please try again')
                sys.exit(0)

            role_arn = awsroles[int(selectedroleindex)].split(',')[0]
            principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
        else:
            role_arn = awsroles[0].split(',')[0]
            principal_arn = awsroles[0].split(',')[1]

        # Use the assertion to get an AWS STS token using Assume Role with SAML
        conn = boto3.client('sts', region_name=region)
        token = conn.assume_role_with_saml(RoleArn=role_arn, PrincipalArn=principal_arn, SAMLAssertion=assertion)

        # Read in the existing config file
        config = configparser.RawConfigParser()
        config.read(credentials)

        # Put the credentials into a saml specific section instead of clobbering
        # the default credentials
        if not config.has_section('saml'):
            config.add_section('saml')

        config['saml']['output'] = outputformat
        config['saml']['region'] = region
        config['saml']['aws_access_key_id'] = token['Credentials']['AccessKeyId']
        config['saml']['aws_secret_access_key'] = token['Credentials']['SecretAccessKey']
        config['saml']['aws_session_token'] = token['Credentials']['SessionToken']

        # Write the updated config file
        with open(credentials, 'w+') as configfile:
            config.write(configfile)

        # Give the user some basic info as to what has just happened
        print('\n\n----------------------------------------------------------------')
        print('Your new access key pair has been stored in the AWS configuration file {0} under the saml profile.'.format(credentials))
        print('Note that it will expire at {0}.'.format(token['Credentials']['Expiration'].astimezone(get_localzone())))
        print('After this time, you may safely rerun this script to refresh your access key pair.')
        print('To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile saml ec2 describe-instances).')
        print('----------------------------------------------------------------\n\n')

        return samladsv3

    except Exception as e:
        print("Error while getting authentication token. %s" % e)


def ec2(self):
    """Makes connection to AWS EC2 using credentials from the specified file."""
    try:
        config = configparser.ConfigParser()
        config.read(self)
        aws_access_key_id = config.get("saml", "aws_access_key_id")
        aws_secret_access_key = config.get("saml", "aws_secret_access_key")
        aws_session_token = config.get("saml", "aws_session_token")
        aws_region = config.get("saml", "region")

    except Exception as e:
        print("Error with credentials. %s" % e)

    try:
        session = boto3.session.Session(profile_name='saml')
        ec2 = session.client('ec2', region_name=aws_region, verify=True, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token)
        return ec2

    except Exception as e:
        print("Error while creating boto3 session. %s" % e)

def get_images(owner, tagvalue):
    """List of AMIs owned by [owner] AND having tag-value of [tagvalue]"""
    try:
        images = ec2(credentials).describe_images(Owners=[owner],Filters=[{'Name':'tag-value', 'Values':[tagvalue]}])
        return images
    except Exception as e:
        print("Error: cannot get the list of images. %s" % e)

############

def query_yes_no(question, default="yes"):
    """Ask a yes/no question via raw_input() and return their answer.
    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).
    The "answer" return value is one of "yes" or "no".
    """
    valid = {"yes":True,   "y":True,  "ye":True,
             "no":False,     "n":False}
    if default == None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("=> Please respond with 'yes' or 'no' "\
                             "(or 'y' or 'n').\n")

def get_non_negative_int(prompt):
    while True:
        try:
            value = int(input(prompt))
        except ValueError:
            print("=> Sorry, your choice must be a number.")
            continue

        if value < 0:
            print("=> Sorry, your response must not be negative.")
            continue

        else:
            break
    return value


def get_remote_file(url):
    """Get the content of the remote file as text. Also disable proxies entirely by not trusting the env."""
    # Disable the proxies by not trusting the env
    session = requests.Session()
    session.trust_env = False

    # Make the request
    requests.packages.urllib3.disable_warnings()
    try:
        r = session.get(url, verify=False)
    except requests.exceptions.RequestException as e:
    # catastrophic error. bail.
        print(e)
        sys.exit(1)

    r = session.get(url, verify=False)
    remote_file = r.text
    return remote_file

def set_termination_date(date):
    suggested_date = datetime.now() + timedelta(days=10)
    formatted_date = suggested_date.strftime('%m/%d/%Y')
    return formatted_date

def readline_input_int(prompt, prefill=''):
    readline.set_startup_hook(lambda: readline.insert_text(prefill))
    try:
        return int(input(prompt))
    except ValueError:
        print("=> Sorry, your choice must be a number.")

    finally:
        readline.set_startup_hook()

def readline_input(prompt, prefill=''):
    readline.set_startup_hook(lambda: readline.insert_text(prefill))
    try:
        return input(prompt)
    finally:
        readline.set_startup_hook()

def fill(arg):
    result = []
    for key, value in arg.items():
        result.append({'Key':key,'Value':value})
    return str(result)[1:-1]

#######
try:
    # Get the full path to credentials file
    credentials = os.path.expanduser("~") + awsconfigfile

    # Check if credentials file exists
    if(os.path.isfile(credentials)):
        pass
    else:
        samladsv3(samladsv3)

    # Check the age of credentials file
    if time.time() - os.path.getmtime(credentials) > 3600:
        samladsv3(samladsv3)

    # Load config file
    cfg = json.loads(get_remote_file(config_file))

    AMI = get_images(cfg['Meta']['Owner'], cfg['Tags']['OSType'])

    # Get the info from the AMI dictionary and fill it in the list.
    image_desc = []
    image_id = []
    print("[-] Available images:")
    for i in AMI['Images']:
        ami_desc = i['Description']
        ami_id = i['ImageId']
        image_desc.append(ami_desc)
        image_id.append(ami_id)
    for index, value in enumerate(image_desc):
        print(" ["+str(index)+"]", value)

    # Prompt for selection of the index number
    selected_version = get_non_negative_int("Select image number: ")
    aws_image_id = image_id[selected_version]



    # Prompt for number of instances to launch
    aws_count = readline_input_int("Enter number of instances: ", "1")

    # Prompt for termination date tag
    aws_termination_date = readline_input("Enter termination date (mm/dd/yyyy): ", set_termination_date("formatted_date"))

    # Fetch the username prefill it into the prompt for the instance name tag
    username = getpass.getuser()
    aws_instance_name = readline_input("Enter instance name (521_something): ", username + '_')

    # Get the info from the InstanceType dictionary and fill it in the list.
    instance_desc = []
    instance_type = []
    print("[-] Available instance types:")
    for key, value in cfg['InstanceType'].items():
        instance_type.append(key)
        instance_desc.append(value)
    for index, value in enumerate(instance_desc):
        print(" ["+str(index)+"]", value)
    selected_type = get_non_negative_int("Select instance type: ")
    aws_instance_type = instance_type[selected_type]

    # User Data script
    answer = query_yes_no("Apply User Data script?")
    if answer == True:
        # Get the info from the InstanceType dictionary and fill it in the list.
        ud_desc = []
        ud_url = []
        print("[-] Available User Data scripts:")
        for key, value in cfg['User-data'].items():
            ud_desc.append(key)
            ud_url.append(value)
        for index, value in enumerate(ud_desc):
            print(" ["+str(index)+"]", value)
        selected_userdata = get_non_negative_int("Select User Data script: ")
        aws_user_data = get_remote_file(ud_url[selected_userdata])
    else:
        aws_user_data = '''#!/bin/bash
        echo 'Built without User Data script' > /etc/motd'''

    conn = ec2(credentials)
    response = conn.run_instances(
        ImageId=aws_image_id,
        MinCount=aws_count,
        MaxCount=aws_count,
        InstanceType=aws_instance_type,
        SubnetId=cfg['Networking']['Subnet'],
        SecurityGroupIds=[
            cfg['Networking']["SecurityGroup"],
        ],
        KeyName=cfg['Key']['Keyname'],
        UserData=aws_user_data,
        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': [
                        {'Key':'Environment','Value':cfg['Tags']['Environment']},
                        {'Key':'OSType','Value':cfg['Tags']['OSType']},
                        {'Key':'Owner','Value':cfg['Tags']['Owner']},
                        {'Key':'APPType','Value':cfg['Tags']['APPType']},
                        {'Key':'BillingContact','Value':cfg['Tags']['BillingContact']},
                        {'Key':'ClarityID','Value':cfg['Tags']['ClarityID']},
                        {'Key':'CostCenter','Value':cfg['Tags']['CostCenter']},
                        {'Key':'SchedulerID','Value':cfg['Tags']['SchedulerID']},
                        {'Key':'TerminationDate','Value':aws_termination_date},
                        {'Key':'Name','Value':aws_instance_name}
                        ]
            },
            {
                'ResourceType': 'volume',
                'Tags': [
                        {'Key':'Environment','Value':cfg['Tags']['Environment']},
                        {'Key':'OSType','Value':cfg['Tags']['OSType']},
                        {'Key':'Owner','Value':cfg['Tags']['Owner']},
                        {'Key':'APPType','Value':cfg['Tags']['APPType']},
                        {'Key':'BillingContact','Value':cfg['Tags']['BillingContact']},
                        {'Key':'ClarityID','Value':cfg['Tags']['ClarityID']},
                        {'Key':'CostCenter','Value':cfg['Tags']['CostCenter']},
                        {'Key':'SchedulerID','Value':cfg['Tags']['SchedulerID']},
                        {'Key':'TerminationDate','Value':aws_termination_date},
                        {'Key':'Name','Value':aws_instance_name}
                        ]
            }
        ]
)

    # Pretty output, print out the whole response
    #pprint(response)

    for i in response['Instances']:
        print("=> Your new", i['InstanceType'], "instance is", i['State']['Name'], "at", i['PrivateIpAddress'])

except Exception as e:
    print("Main: %s" % e)
    traceback.print_exc()
