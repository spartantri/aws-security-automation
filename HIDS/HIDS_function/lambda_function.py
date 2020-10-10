import json
import urllib.parse
import base64
import datetime
import time
import logging
import log
import zlib
import os
import boto3
import requests
# import uuid
from requests_aws4auth import AWS4Auth
from botocore.client import Config
from types import SimpleNamespace

endpoint = os.environ['ES_ENDPOINT']
logger = log.setup_custom_logger('root')
if "loglevel" in os.environ:
    loglevel = os.environ.get("loglevel")
    print("Setting log level to : %s" % loglevel)
    if loglevel.lower() == "debug":
        logger.setLevel(logging.DEBUG)
    elif loglevel.lower() == "info":
        logger.setLevel(logging.INFO)
    elif loglevel.lower() == "warning":
        logger.setLevel(logging.WARNING)
    elif loglevel.lower() == "error":
        logger.setLevel(logging.ERROR)
    else:
        logger.setLevel(logging.CRITICAL)
else:
    logger.setLevel(logging.CRITICAL)

AWS_REGION = os.environ['AWS_REGION']

config = Config(connect_timeout=3, retries={'max_attempts': 1}, region_name=AWS_REGION)
s3_client = boto3.client('s3', config=config)
sqs_client = boto3.client('sqs', config=config)
sns_client = boto3.client('sns', config=config)
ec2_client = boto3.client('ec2', config=config)
lambda_client = boto3.client('lambda', config=config)


def get_creds(region, service):
    """
    This helper function gets the AWS credentials eiter from a specific profile if it is defined as environment variable
    or use the default credentials.
    """
    # Get AWS temporary credentials
    if "AWS_PROFILE" in os.environ:
        AWS_PROFILE = os.environ.get("AWS_PROFILE")
        credentials = boto3.Session(profile_name=AWS_PROFILE).get_credentials()
    else:
        credentials = boto3.Session().get_credentials()
    # Build authentication credentials to use with requests
    awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, region, service,
                       session_token=credentials.token)
    return awsauth


def parse_awslogs(event):
    try:
        awslogsData = json.loads(zlib.decompress(base64.b64decode(event['awslogs']['data']), 16 + zlib.MAX_WBITS))
    except json.decoder.JSONDecodeError:
        logger.error("JSON parsing error")
        logger.error(str(event))
    except:
        logger.error("Unknown parsing error")
        logger.debug(str(event))
    return awslogsData


def parse_guardduty(event):
    awslogsData = dict()
    awslogsData['messageType'] = 'DATA_MESSAGE'
    # print(event)
    if 'source' in event:
        if event['source'] == "aws-guardduty-s3-backup":
            try:
                guarddutys3account = event['logEvents'][0]['accountId']
                awslogsData['owner'] = guarddutys3account
            except KeyError:
                logger.debug("Received content fo type {}".format(type(event['logEvents'])))
            awslogsData['logGroup'] = event['source']
            awslogsData['logStream'] = "GuardDuty Finding"
            awslogsData['logEvents'] = [{}]
            for recordcount in range(len(event['logEvents'])):
                record = dict()
                record['message'] = json.dumps(event['logEvents'][recordcount])
                try:
                    record['timestamp'] = time.mktime(
                        time.strptime(event['logEvents'][recordcount]['time'], "%Y-%m-%dT%H:%M:%SZ")) * 1000
                    record['id'] = event['logEvents'][recordcount]['id']
                except KeyError:
                    record['timestamp'] = int(time.time() * 1000)
                    record['id'] = float(time.time() * 1000)
                    logger.debug("Received message is missing keys, found only {}".format(
                        event['logEvents'][recordcount].keys()))
                    logger.debug(event['logEvents'][recordcount])
                awslogsData['logEvents'].append(record)
            # IMPLEMENT s3 source
        else:
            awslogsData['owner'] = event['account']
            awslogsData['logGroup'] = event['source'].replace('.', '-')
            awslogsData['logStream'] = event['detail-type']
            awslogsData['logEvents'] = [{}]
            awslogsData['logEvents'][0]['message'] = json.dumps(event)
            awslogsData['logEvents'][0]['timestamp'] = time.mktime(
                time.strptime(event['time'], "%Y-%m-%dT%H:%M:%SZ")) * 1000
            awslogsData['logEvents'][0]['id'] = event['id']
    else:
        logger.info("Received event containing the following keys {}".format(event.keys()))
    return awslogsData


def parse_multijson(rawpayload):
    nice_json = []
    payload = rawpayload.split('\n')
    # logger.info(payload[0])
    for record in range(len(payload)):
        try:
            logger.debug("Header  :" + str(payload[record])[2:10])
            logger.debug("Trailer :" + str(payload[record])[-10:-3])
            nice_json.append(json.loads(str(payload[record])[2:-3]))
        except json.decoder.JSONDecodeError:
            nice_json.append({"message": payload[record]})
            logger.info(payload[record][2:400])
    logger.debug("Generating event of type {}".format(type(nice_json)))
    logger.debug("Generating event of size {}".format(str(len(nice_json))))
    return nice_json


def parse_s3(event):
    awslogsData = dict()
    awslogsData['messageType'] = 'DATA_MESSAGE'
    awslogsData['logEvents'] = [{}]
    key = event['s3']['object']['key'].split('/')
    if 'AWSLogs' in key:
        for prefix in range(len(key)):
            if key[prefix] == 'AWSLogs':
                if key[prefix + 1].isdigit():
                    awslogsData['owner'] = key[prefix + 1]
                    awslogsData['logGroup'] = '-'.join([key[prefix], key[prefix + 2]])
                else:
                    awslogsData['owner'] = event['s3']['bucket']['ownerIdentity']['principalId']
                    awslogsData['logGroup'] = 'AWSLogs'
                awslogsData['logStream'] = awslogsData['owner']
                break
    awslogsData['logEvents'][0]['message'] = json.dumps(event)
    awslogsData['logEvents'][0]['timestamp'] = int(
        time.mktime(time.strptime(event['eventTime'], "%Y-%m-%dT%H:%M:%S.%fZ")) * 1000)
    awslogsData['logEvents'][0]['id'] = key[len(key) - 1].split('.')[0]
    if awslogsData['logGroup'] == "AWSLogs-GuardDuty":
        bucket = event['s3']['bucket']['name']
        objectkey = urllib.parse.unquote_plus(event['s3']['object']['key'], encoding='utf-8')
        guarddutys3object = dict()
        guarddutys3object['bucket'] = bucket
        guarddutys3object['key'] = objectkey
        logger.info("Generating S3 backup event for: {}".format(str(guarddutys3object)))
        logger.debug("Received event: {}".format(str(event)))
        obj = s3_client.get_object(Bucket=bucket, Key=objectkey)['Body'].read()
        if key[len(key) - 1].split('.')[-1] == "gz":
            decompressed = str(zlib.decompress(obj, 16 + zlib.MAX_WBITS))
        else:
            decompressed = obj
        try:
            content = [json.loads(decompressed)]
        except json.decoder.JSONDecodeError:
            content = parse_multijson(decompressed)
            logger.debug("Exception while processing payload of type {}".format(type(content)))
            logger.debug("Exception while processing payload of le {}".format(len(content)))
            logger.debug("Exception while processing payload setting content to: {}".format(content))
        s3event = dict()
        s3event['source'] = "aws-guardduty-s3-backup"
        s3event['logEvents'] = content
        s3event['full_log'] = decompressed
        # logger.info(str(s3event['logEvents'])[0:200])
        # logger.info(type(s3event['logEvents']))
        # logger.info(s3event.keys())
        # logger.info(len(s3event['logEvents']))
        parse_guardduty(s3event)
    return awslogsData


def parse_cloudtrail(event):
    awslogsData = dict()
    awslogsData['messageType'] = 'DATA_MESSAGE'
    awslogsData['owner'] = event['account']
    awslogsData['logGroup'] = 'CloudTrail'
    awslogsData['logStream'] = awslogsData['owner']
    awslogsData['logEvents'] = [{}]
    awslogsData['logEvents'][0]['message'] = event['detail']['eventName']
    awslogsData['logEvents'][0]['timestamp'] = int(
        time.mktime(time.strptime(event['detail']['eventTime'], "%Y-%m-%dT%H:%M:%SZ")) * 1000)
    awslogsData['logEvents'][0]['id'] = event['detail']['eventID']
    return awslogsData


def send(ParsedData):
    response = dict()
    ProcessedData = transform(ParsedData)
    elasticsearchBulkData = ProcessedData['message']
    for logEvent in ParsedData['logEvents']:
        try:
            message = json.loads(logEvent['message'])
        except json.decoder.JSONDecodeError:
            break
        logger.debug("No log level recorded on event {}".format(logEvent['message']))
        logger.debug("No log level recorded on event {}".format(json.loads(logEvent['message']).keys()))
        if 'rule' in message:
            logger.debug(message['rule'].keys())
            if 'level' in message['rule']:
                if 'rule.level' in ProcessedData:
                    if message['rule']['level'] > ProcessedData['rule.level']:
                        ProcessedData['rule.level'] = message['rule']['level']
                else:
                    ProcessedData['rule.level'] = message['rule']['level']
            else:
                logger.debug("Fields in message {}".format(message.keys()))
        else:
            if 'detail' in message:
                if 'severity' in message['detail']:
                    logger.debug(message['detail'].keys())
                    ProcessedData['rule.level'] = int(round(message['detail']['severity'] * 1.5))
                else:
                    logger.info(message['detail'].keys())
            else:
                logger.info(message.keys())
    if 'rule.level' in ProcessedData:
        response['rule.level'] = ProcessedData['rule.level']
        logger.debug("Event with rule level {} detected".format(response['rule.level']))
        if 'IncidentThreshold' in os.environ and 'IR_SNS' in os.environ:
            if response['rule.level'] >= int(os.environ['IncidentThreshold']):
                logger.info("Event with rule level exceeding threshold {}, will trigger SNS to {}".format(
                    response['rule.level'], os.environ['IR_SNS']))
                logger.debug(ProcessedData.keys())
                target = ""
                if 'instanceID' in ProcessedData:
                    response['instanceID'] = ProcessedData['instanceID']
                    target = response['instanceID']
                    logger.info("Target instanceID: {}".format(response['instanceID']))
                else:
                    if '@log_stream' in ProcessedData:
                        response['@log_stream'] = ProcessedData['@log_stream']
                        if response['@log_stream'][0:2] == "i-" and len(response['@log_stream']) > 7 and len(
                                response['@log_stream']) < 20:
                            target = response['@log_stream']
                        logger.info("Target log_stream: {}".format(response['@log_stream']))
                    else:
                        if 'srcip' in ProcessedData:
                            response['srcip'] = ProcessedData['srcip']
                            logger.info("Target srcip: {}".format(response['srcip']))
                        else:
                            if 'hostname' in ProcessedData:
                                response['hostname'] = ProcessedData['hostname']
                                response['srcip'] = response['hostname'][3:].split(".")[0].replace("-", ".")
                                logger.info("Target hostname: {}".format(response['hostname']))
                                logger.info("Target srcip: {}".format(response['srcip']))

                if target == "":
                    if 'srcip' in response:
                        logger.debug("Searching instance id for {}".format(response['srcip']))
                        target = get_instance_byip(response['srcip'])

                if len(target) > 7:
                    logger.warning("Started incident handling for {}".format(target))
                    # .detail["resource"]["instanceDetails"]["instanceId"]
                    # sns_message = json.dumps({"default":{"detail":{"instanceID": target, "supportID": {"instanceID": target}}}})
                    sns_message = json.dumps({"detail": {"resource": {"instanceDetails": {"instanceId": target}}}})
                    logger.debug((json.dumps(sns_message)))
                    sns_response = sns_client.publish(TopicArn=os.environ['IR_SNS'], Message=sns_message)
                    logger.info(sns_response)
    else:
        logger.debug("No log level recorded on event {}".format(ProcessedData.keys()))
    r = post(elasticsearchBulkData)
    response['text'] = r.text
    logger.debug(str(response))
    return response


def get_instance_byip(srcip):
    instances = ec2_client.describe_instances()
    for instance in instances:
        if instance['private-ip-address'] == srcip:
            instanceID = instance['instance-id']
    return instanceID


def trigger_incident(event):
    return


def lambda_handler(event, context):
    response = "Event could not be processed"
    if 'awslogs' in event:
        response = send(parse_awslogs(event))
    else:
        if 'source' in event and event['detail-type'] in ["GuardDuty Finding"]:
            response = send(parse_guardduty(event))
        else:
            if 'Records' in event:
                for record in event['Records']:
                    response = send(parse_s3(record))
            else:
                if 's3' in event and 'eventSource' in event:
                    if event['eventSource'] == "aws:s3":
                        response = send(parse_s3(event))
                else:
                    if "detail-type" in event and event['detail-type'] == "AWS API Call via CloudTrail":
                        response = send(parse_cloudtrail(event))
                        logger.debug("Received event with the following keys: {}".format(event.keys()))
                    else:
                        response = 'UNKNOWN LOG SOURCE TYPE'
                        logger.error(json.dumps(event))

    return {
        'statusCode': 200,
        'body': json.dumps(response['text'])
    }


def vpcflow_to_json(flowlog):
    flowLogRaw = flowlog.split()
    flowLog = dict()
    flowLog['version'] = flowLogRaw[0]
    flowLog['account'] = flowLogRaw[1]
    flowLog['interfaceId'] = flowLogRaw[2]
    flowLog['srcip'] = flowLogRaw[3]
    flowLog['dstip'] = flowLogRaw[4]
    flowLog['srcport'] = flowLogRaw[5]
    flowLog['dstPort'] = flowLogRaw[6]
    flowLog['ianaProtocol'] = flowLogRaw[7]
    flowLog['packets'] = flowLogRaw[8]
    flowLog['bytes'] = flowLogRaw[9]
    flowLog['startTimeUnix'] = int(flowLogRaw[10])
    flowLog['endTimeUnix'] = int(flowLogRaw[11])
    flowLog['flowAction'] = flowLogRaw[12]
    flowLog['timestampFlowStart'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(flowLog['startTimeUnix']))
    flowLog['timestampFlowEnd'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(flowLog['endTimeUnix']))
    flowLog['eniArn'] = ''.join(
        ['arn:aws:ec2:', AWS_REGION, ':', flowLog['account'], ':network-interface/', flowLog['interfaceId']])
    return flowLog


def transform(payload):
    RequestBody = dict()
    try:
        if payload['messageType'] == 'CONTROL_MESSAGE':
            return
    except KeyError:
        logger.error("No AWS logs data received")
        logger.debug(str(payload))
    bulkRequestBody = ''
    for logEvent in payload['logEvents']:
        timestamp = time.gmtime(logEvent['timestamp'] / 1000)
        indexName = 'cwl-'
        indexName += '.'.join(
            ['{:04d}'.format(timestamp.tm_year), '{:02d}'.format(timestamp.tm_mon), '{:02d}'.format(timestamp.tm_mday)])
        source = dict()
        if payload['logGroup'] == os.environ['VPCFlowLogGroup']:
            logger.debug("Decorating vpc flow log to be implemented")
            if 'extractedFields' in logEvent:
                logger.debug(str(logEvent['extractedFields']))
                if 'srcaddr' in logEvent['extractedFields']:
                    extractedFields = logEvent['extractedFields']
                    flowLog = dict()
                    flowLog['account'] = extractedFields['account_id']
                    flowLog['interfaceId'] = extractedFields['interface_id']
                    flowLog['srcip'] = extractedFields['srcaddr']
                    flowLog['dstip'] = extractedFields['dstaddr']
                    flowLog['srcport'] = extractedFields['srcport']
                    flowLog['dstPort'] = extractedFields['dstport']
                    flowLog['ianaProtocol'] = extractedFields['protocol']
                    flowLog['startTimeUnix'] = int(extractedFields['start'])
                    flowLog['endTimeUnix'] = int(extractedFields['end'])
                    flowLog['flowAction'] = extractedFields['action']
                    flowLog['logstatus'] = extractedFields['log_status']
                    flowLog['packets'] = extractedFields['packets']
                    flowLog['bytes'] = extractedFields['bytes']
                    flowLog['version'] = extractedFields['version']
                    flowLog['timestampFlowStart'] = time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                                                  time.gmtime(flowLog['startTimeUnix']))
                    flowLog['timestampFlowEnd'] = time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                                                time.gmtime(flowLog['endTimeUnix']))
                    flowLog['eniArn'] = ''.join(
                        ['arn:aws:ec2:', AWS_REGION, ':', flowLog['account'], ':network-interface/',
                         flowLog['interfaceId']])
                    source.update(flowLog)
                else:
                    source.update(vpcflow_to_json(logEvent['message']))
            if 'flowAction' in source:
                source['rule.comment'] = ''.join([source['flowAction'], " VPCFlow log"])
                if source['flowAction'] == "ACCEPT":
                    source['rule.level'] = 2
                elif source['flowAction'] == "REJECT":
                    source['rule.level'] = 6
        try:
            source = json.loads(logEvent['message'])
        except json.decoder.JSONDecodeError:
            debugerror = ''.join(["JSON parsing error", str(payload)])
            logger.debug(debugerror)
        source['@id'] = logEvent['id']
        source['@timestamp'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', timestamp)
        source['@message'] = logEvent['message']
        source['@owner'] = payload['owner']
        source['@log_group'] = payload['logGroup']
        source['@log_stream'] = payload['logStream']
        source['timedelta'] = (
                datetime.datetime.fromtimestamp(time.mktime(timestamp)) - datetime.datetime.now()).total_seconds()
        source['timestampprocessed'] = datetime.datetime.utcnow().isoformat()
        if "GuardDuty" in source['@log_stream']:
            source['rule.level'] = round(source['detail']['severity'] * (15 / 10))
            source['rule.comment'] = source['detail']['title']
        if "AWSLogs-GuardDuty" in source['@log_group']:
            source['rule.level'] = 3
            source['rule.comment'] = "GuardDuty S3 backup received"
        action = {"index": {}}
        action['index']['_index'] = indexName
        action['index']['_type'] = 'IDS'
        action['index']['_id'] = logEvent['id']
        bulkRequestBody += '\n'.join([json.dumps(action), json.dumps(source)]) + '\n'
    if 'rule.level' in source:
        RequestBody['rule.level'] = source['rule.level']
    if 'srcip' in source:
        RequestBody['srcip'] = source['srcip']
    if 'hostname' in source:
        RequestBody['srcip'] = source['hostname']
    if '@log_stream' in source:
        RequestBody['@log_stream'] = source['@log_stream']
    if 'detail' in source:
        RequestBody['instanceID'] = source['detail']['resource']['instanceDetails']['instanceId']
        logger.debug(source['detail']['resource']['instanceDetails']['instanceId'])
    RequestBody['message'] = bulkRequestBody

    return RequestBody


def create_sechub_finding():
    securityhub = boto3.client("securityhub")
    return


def post(body):
    AWS_SERVICE = 'es'
    awsauth = get_creds(AWS_REGION, AWS_SERVICE)
    url = ''.join(["https://", endpoint, "/_bulk"])
    header = {"Accept": "*/*", "Accept-Encoding": "gzip, deflate", "Content-Type": "application/json"}
    response = requests.post(url, auth=awsauth, data=body, headers=header)
    # logger.info("Posted event to ES with keys {}".format(json.loads(body).keys()))
    return response