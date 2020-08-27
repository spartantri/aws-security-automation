# MIT No Attribution

# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import boto3
import json
import logging
import os
from botocore.config import Config as BotoCoreConfig

# from base64 import b64decode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib import parse

region=os.environ['AWS_REGION']
boto_config = BotoCoreConfig(read_timeout=65, region_name=region)
client = boto3.client('stepfunctions', config=boto_config)

HOOK_URL = os.environ['HookUrl']
# The Slack channel to send a message to stored in the slackChannel environment variable
SLACK_CHANNEL = os.environ['SlackChannel']
activityArn = os.environ['ActivityArn']

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


slack_ping = {
        "attachments": [
            {
                "fallback": "Check kill or leave hearthbeat.",
                "color": "#b7121a",
                "title": "Check kill or leave hearthbeat.",
                "text": "",
                "fields": [{
                        "value": "Check kill or leave hearthbeat."
                    }]
            }
        ]
    }


def lambda_handler(event, context):
    #req = Request(HOOK_URL, json.dumps(slack_ping).encode('utf-8'))
    #ping = urlopen(req)
    #ping.read()
    #logger.info("Ping posted to %s", SLACK_CHANNEL)
    try:
        response = client.get_activity_task(activityArn=activityArn,workerName='sec-ir-A')
        logger.info(response)
    except:
        logger.info("No activities scheduled")
        return
    if 'taskToken' in response:
        logger.info("Received taskToken {}".format(response['taskToken']))
        logger.info(response)
    else:
        logger.info("No taskToken received")
        return
    #instanceID = event['input']['instanceID']
    #status = event['input']['STATUS']
    instanceID="i-99999999"
    status = 'DONE'
    taskToken = response['taskToken']
    slack_message_text = formatMyMessage(instanceID, status, taskToken)
    logger.info(slack_message_text)
    # slack_message_text = response
    req = Request(HOOK_URL, json.dumps(slack_message_text).encode('utf-8'))
    try:
        response = urlopen(req)
        response.read()
        logger.info("Message posted to %s", SLACK_CHANNEL)
    except HTTPError as e:
        logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
        logger.error("Server connection failed: %s", e.reason)

    return


def formatMyMessage(instanceID, status, taskToken):
    title = "Authorization required!! \n Security Incident handled \n"
    title += " Instance Isolated due to security incident detected : " + instanceID
    previous_steps = '\n 1. Instance isolated with quarantine SG and NACL \n'
    previous_steps += ' 2. Snapshot of the volume stored \n'
    previous_steps += ' 3. Forensic Instance created and the volume was mounted for forensic analysis \n'
    previous_steps += ' 4. Forensic analysis of volume performed \n'
    previous_steps += ' 5. Forensic report sent to security channel'
    kill_link = '\n To Kill the affected instance go to : \n'
    kill_link += 'https://09szp219il.execute-api.us-west-2.amazonaws.com/DFIR/kill-it?taskToken=' + parse.quote_plus(taskToken)
    leave_link = '\n To keep the affected instance running in quarantine go to : \n'
    leave_link += 'https://09szp219il.execute-api.us-west-2.amazonaws.com/DFIR/leave-it?taskToken=' + parse.quote_plus(taskToken)
    slack_message = {
        "attachments": [
            {
                "fallback": "Kill instance or leave it in quarantine.",
                "color": "#b7121a",
                "title": title,
                "text": "",
                "fields": [{
                        "value": "Previous steps : " + previous_steps
                    },
                    {
                        "value": "Instance under isolation: " + instanceID
                    },
                    {
                        "value": "Current status of the task : " + status
                    },
                    {
                        "value": "Kill instance : " + kill_link
                    },
                    {
                        "value": "Quarantine instance : " + leave_link
                    }]
            }
        ]
    }
    return slack_message
