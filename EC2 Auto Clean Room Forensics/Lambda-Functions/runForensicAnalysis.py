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
    InitialSetup = ['#!/bin/bash','date -u +"%Y-%m-%dT%H:%M:%SZ"',
                'sudo mkfs /dev/xvdg','sudo mkdir /forensics','sudo mount /dev/xvdg /forensics',
                'sudo apt-get install sleuthkit hashdeep -y', 'sudo apt-get install cloud-utils -y']
    SIFTinstall = [ 'sudo apt update -y',
                'sudo curl -Lo /usr/local/bin/sift https://github.com/sans-dfir/sift-cli/releases/download/v1.8.5/sift-cli-linux',
                'sudo chmod +x /usr/local/bin/sift', 'sudo sift install --mode=server', 'sudo sift update']
    Forensicate = ['sudo dd if=/dev/xvdf1 of=/forensics/' + instanceID + '.dd',
                'sudo fls -r -m -i /forensics/' + instanceID + '.dd >/forensics/file-full-' + instanceID + '.txt',
                'sudo mactime -b /forensics/file-full-' + instanceID + '.txt $date >/forensics/file-mac-' + instanceID + '.txt',
                'sudo fls -rd /forensics/' + instanceID + '.dd >/forensics/file-deleted-' + instanceID + '.txt']
    Reporting = ['EC2_INSTANCE_ID=$(ec2metadata --instance-id)',
                'cp /forensics/file-deleted-' + instanceID + '.txt /forensics/file-deleted-$EC2_INSTANCE_ID-' + instanceID+ '.txt',
                'cp /forensics/file-mac-' + instanceID + '.txt /forensics/$EC2_INSTANCE_ID.txt',
                'cp /forensics/file-full-' + instanceID + '.txt /forensics/file-full-$EC2_INSTANCE_ID.txt',
                'aws s3 cp /forensics/file-full-' + instanceID + '.txt s3://' + S3BucketName + '/incident-response/' + instanceID + '/',
                'aws s3 cp /forensics/file-deleted-' + instanceID + '-' + instanceID + '.txt s3://' + S3BucketName + '/incident-response/' + instanceID+ '/',
                'aws s3 cp /forensics/file-mac-' + instanceID + '.txt s3://' + S3BucketName +'/incident-response/' + instanceID + '/']
    AlternativeForensics = ['if [ "$(find /forensics/file-full-' + instanceID + '.txt -printf %s)" == "0" ]; then exit; fi',
                'sudo mkdir /mnt/' + instanceID, 'target=$(sudo losetup --partscan --fin --show /forensics/' + instanceID + ')',
                'sudo mount $target /mnt/' + instanceID,
                'sudo find /mnt/' + instanceID + ' -type f -printf "%P,%A+,%T+,%C+,%u,%g,%M,%s\n" >/forensics/file-mac-' + instanceID + '.txt',
                'sudo hashdeep /mnt/' + instanceID + '-r >/forensics/file-mac-' + instanceID + '.txt']
    commands = InitialSetup + Forensicate + Reporting + AlternativeForensics + Reporting
    if 'InstallSIFT' in os.environ:
        if os.environ['InstallSIFT'].lower() == "yes":
            commands = commands + SIFTinstall

    response = ssmclient.send_command(
        InstanceIds= [event.get('ForensicInstanceId')],
        DocumentName='AWS-RunShellScript',
        Parameters={
            'commands': commands,
            'executionTimeout': ['3600'] # Seconds all commands have to complete in
            },
        Comment='SSM Command Execution',
        # sydney-summit-incident-response
        OutputS3Region=S3BucketRegion,
        OutputS3BucketName=S3BucketName,
        OutputS3KeyPrefix=event.get('ForensicInstanceId')
        )
    print(response)
    return event
