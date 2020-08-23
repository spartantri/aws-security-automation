# MIT No Attribution

# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import boto3

elbv2client = boto3.client('elbv2')

# Isolate Instance from EC@ autoscaling
autoscalingclient = boto3.client('autoscaling')
ec2 = boto3.resource('ec2')


# Get Autoscaling instance matching the instanceID
def get_asginstances_byid(instanceID):
    AutoScalingInstances = autoscalingclient.describe_auto_scaling_instances(
        InstanceIds=[instanceID]
        )['AutoScalingInstances'][0]
    print(AutoScalingInstances)

    print("Processing autoscaling group: {}".format(AutoScalingInstances['AutoScalingGroupName']))
    AutoScalingGroupName = AutoScalingInstances['AutoScalingGroupName']

    return AutoScalingGroupName


# Isolate instance from the Autoscaling group
def isolateInstanceASG(instanceID, AutoScalingGroupName):
    print(instanceID)
    print(AutoScalingGroupName)
    from os import environ
    if 'ShouldDecrementDesiredCapacity' in environ:
        if environ['ShouldDecrementDesiredCapacity'].lower() == "true":
            ShouldDecrementDesiredCapacity = True
        else:
            ShouldDecrementDesiredCapacity = False
    else:
        ShouldDecrementDesiredCapacity = False
    response = autoscalingclient.detach_instances(
        InstanceIds=[instanceID], AutoScalingGroupName=AutoScalingGroupName,
        ShouldDecrementDesiredCapacity=ShouldDecrementDesiredCapacity
    )
    print(response)
    return 'SUCCEEDED'


# Isolate Instance from ALB
def isolateInstanceALBv2(instanceID, targetGroupsARN):
    print(instanceID)
    print(targetGroupsARN)
    response = elbv2client.deregister_targets(
        TargetGroupArn=targetGroupsARN,
        Targets=[
            {
                'Id': instanceID
            },
        ]
    )
    print(response)
    return 'SUCCEEDED'


# Instance ID is passed as parameter
# Leverages elbv2 SDK to retrieve the details of ELB where the instance is attached
# Invokes deregister targets to deregister the instance
def lambda_handler(event, context):
    print(event)
    instanceID = event.get('instanceID')
    response = 'FAILED'
    targetGroups = elbv2client.describe_target_groups()
    AutoScalingGroupName = get_asginstances_byid(instanceID)
    if targetGroups:
        # Iterates ELB and gets the ELB where the instance is attached
        for key in targetGroups['TargetGroups']:
            targetGroupArn = key.get('TargetGroupArn')
            targets = elbv2client.describe_target_health(
                TargetGroupArn=targetGroupArn
            )

            instanceIDlist = []
            for instanceKey in targets['TargetHealthDescriptions']:
                instanceIDlist.append(instanceKey.get('Target').get('Id'))

            if instanceID in instanceIDlist:
                response = isolateInstanceALBv2(instanceID, targetGroupArn)
    if AutoScalingGroupName:
        response = isolateInstanceASG(instanceID, AutoScalingGroupName)
    event['STATUS'] = response
    event['targetGroupArn'] = targetGroupArn
    return event
