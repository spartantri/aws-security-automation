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
import os


ssmclient = boto3.client('ssm')


def lambda_handler(event, context):
    print(event)
    instanceID = event['instanceID']
    S3BucketName = os.environ['OUTPUT_S3_BUCKETNAME']
    S3BucketRegion = os.environ['OUTPUT_S3_BUCKETREGION']
    commands = ['#!/bin/bash','date -u +"%Y-%m-%dT%H:%M:%SZ"',
                'sudo mkfs /dev/xvdg','sudo mkdir /forensics','sudo mount /dev/xvdg /forensics',
                'dd if=/dev/xvdf1 of=/forensics/' + instanceID + '.dd',
                'fls -r -m -i /forensics/' + instanceID + '.dd >~/file-full-' + instanceID + '.txt',
                'mactime -b ~/file-full-' + instanceID + '.txt $date >~/file-mac-' + instanceID + '.txt',
                'fls -rd /forensics/' + instanceID + '.dd >~/file-deleted-' + instanceID + '.txt',
                'sudo apt-get install cloud-utils ',
                'EC2_INSTANCE_ID=$(ec2metadata --instance-id)',
                'cp ~/file-deleted-' + instanceID + '.txt ~/file-deleted-$EC2_INSTANCE_ID-' + instanceID+ '.txt',
                'cp ~/file-mac-' + instanceID + '.txt ~/$EC2_INSTANCE_ID.txt',
                'cp ~/file-full-' + instanceID + '.txt ~/file-full-$EC2_INSTANCE_ID.txt',
                'aws s3 cp ~/file-full-' + instanceID + '.txt s3://' + S3BucketName + '/incident-response/' + instanceID + '/',
                'aws s3 cp ~/file-deleted-' + instanceID + '-' + instanceID + '.txt s3://' + S3BucketName + '/incident-response/' + instanceID+ '/',
                'aws s3 cp ~/file-mac-' + instanceID + '.txt s3://' + S3BucketName +'/incident-response/' + instanceID + '/']
    
    
    response = ssmclient.send_command(
        InstanceIds= [event.get('ForensicInstanceId')],
        DocumentName='AWS-RunShellScript',
        Parameters={
            'commands': commands,
            'executionTimeout': ['600'] # Seconds all commands have to complete in
            },
        Comment='SSM Command Execution',
        # sydney-summit-incident-response
        OutputS3Region=S3BucketRegion,
        OutputS3BucketName=S3BucketName,
        OutputS3KeyPrefix=event.get('ForensicInstanceId')
        )
    print(response)
    return event
