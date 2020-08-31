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
ec2 = boto3.resource('ec2')

# Remove NACL from Egress or Ingress
Egress = False


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
                print("Terminating instance : ", instanceID)
                remove_nacl(instanceID)
                response = ec2client.terminate_instances(InstanceIds=[instanceID])
                return 'SUCCEEDED'
    return 'FAILED'


def remove_nacl(instanceID):
    from os import environ
    upstreamsubnetID = ""
    upstreamVPCID = ""
    if 'upstreamsubnetID' in environ:
        upstreamsubnetID = environ.get('upstreamsubnetID')
    else:
        return
    if 'upstreamVPCID' in environ:
        upstreamVPCID = environ.get('upstreamVPCID')
    Instances = ec2client.describe_instances(
        InstanceIds=[instanceID]
    )
    if len(Instances) > 0:
        VPCID = Instances['Reservations'][0]['Instances'][0]['VpcId']
        SubnetID = Instances['Reservations'][0]['Instances'][0]['SubnetId']
        cidr = Instances['Reservations'][0]['Instances'][0]['NetworkInterfaces'][0]['PrivateIpAddresses'][0]['PrivateIpAddress'] + "/32"
        for nacl in ec2client.describe_network_acls()['NetworkAcls']:
            if nacl['VpcId'] == upstreamVPCID:
                for association in nacl['Associations']:
                    if association['SubnetId'] == upstreamsubnetID:
                        rule = find_rule(nacl['Entries'], cidr)
                        if rule > 0:
                            naclID = nacl['NetworkAclId']
                            response = ec2client.delete_network_acl_entry(
                                NetworkAclId=naclID,Egress=Egress,RuleNumber=rule
                                )
                            print(response)
                            return
    return


def find_rule(entries, cidr):
    if len(entries) == 0:
        return 0
    for entry in entries:
        if entry['Egress'] == Egress and entry['CidrBlock'] == cidr and entry['RuleAction'] == 'deny':
            return entry['RuleNumber']
    print("No matching NACLs found")
    return 0


def lambda_handler(event, context):
    print(event)
    instanceID = event.get('instanceID')
    # tag_instance(instanceID)
    response = 'FAILED'
    response = get_instance_by_id(instanceID)
    event['STATUS'] = response
    return event
