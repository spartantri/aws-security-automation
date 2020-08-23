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
from botocore.vendored import requests

client = boto3.client('s3')

HOOK_URL = os.environ['HookUrl']
# The Slack channel to send a message to stored in the slackChannel environment variable
SLACK_CHANNEL = os.environ['SlackChannel']
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    print(event)
    accountID = context.invoked_function_arn.split(":")[4]
    # bucket = event['Records'][0]['s3']['bucket']['name']
    # key = event['Records'][0]['s3']['object']['key']
    bucket = os.environ['OUTPUT_S3_BUCKETNAME']
    key = "/incident-response/" + event['instanceID'] + '/' + event['instanceID'] + '.txt'
    print("Sending report {}{}".format(bucket, key))

    try:
        response = client.get_object(
            Bucket=bucket,
            Key=key
        )
        # print (response)
        content = response['Body'].read()
        # print(content)
        array = []
        linearray = content.splitlines()
        # print (linearray)
        for s in linearray:
            # print (s)

            if "d/r *" in str(s):
                # print (s)
                array.append('"' + str(s) + '"')

        print(array)
        # json_message = json.loads(json.loads(event['Records'][0]['Sns']['Message'])['TextMessage'])
        instanceList = key.replace('incident-response/file-deleted-', '').replace(".txt", "")
        print(instanceList)
        instanceArray = instanceList.split("-i-")
        slack_message_text = formatMyMessage(
            "i-" + instanceArray[1], instanceArray[0], array, "s3://" + bucket + "/" + key, accountID
        )
        # Sends the message to Slack
        response = requests.post(
            HOOK_URL, data=json.dumps(slack_message_text), headers={'Content-Type': 'application/json'}
        )
        logging.info("Response Status Code: ")
        # logging.info(response.status_code)
    except:
        logger.error("Failed to send report {}{}".format(bucket, key))
    return event


def formatMyMessage(victimInstanceID, instanceID, deletedLines, s3location, accountID):
    title = "Results for instance " + victimInstanceID + " being investigated for deleted files\n "
    title += " \n For more information login to forensics instance : " + instanceID
    title += " \n AWS Account: " + accountID + " \n S3 Location: " + s3location
    slack_message = {
        "attachments": [
            {
                "fallback": "Required plain-text summary of the attachment.",
                "color": "#b7121a",
                "title": title,
                "text": "",
                "fields": [{
                    "value": "Details: " + '\n '.join(deletedLines)
                },
                    {
                        "value": "For More details Login to the instance: " + instanceID
                    }]
            }
        ]
    }
    return slack_message
