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

ec2client = boto3.client('ec2')


# Check if instance exists
def get_instance_by_id(instanceID):
    Instances = ec2client.describe_instances(
        InstanceIds=[instanceID]
        )
    if len(Instances)>0:
        TaggedInstances = ec2.instances.filter(
            Filters=[{'Name': 'tag:IsInstanceUnderForensics', 'Values': ['Yes']}], InstanceIds=[instanceID]
        )
        for instance in TaggedInstances:
            if instance.id == instanceID:
                print("Terminating instance %s", instanceID)
                response = ec2client.terminate_instances(
                    InstanceIds=[instanceID]
                print(response)
                return 'SUCCEEDED'
    return 'FAILED'


def lambda_handler(event, context):
    print(event)
    instanceID = event.get('instanceID')
    # tag_instance(instanceID)
    response = 'FAILED'
    response = get_instance_by_id(instanceID)
    event['STATUS'] = response
    return event