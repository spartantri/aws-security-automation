AssignPublicIP="true"
ESInstanceSize="m5.large.elasticsearch"
HIDSInstanceQuantity=2
HIDSInstanceSize="t2.micro"
MyKeyPair="MY-KEY"
MyS3Bucket="MY-BUCKET-hids"
MyS3Key="hids-lambda-consumer.zip"
MyTrustedNetwork="172.31.0.0/16"
SubnetId="subnet-SUBNET-ID"
VPCId="vpc-VPC-ID"
region="us-west-2"
stack="HIDS"
template="hids-cwl-es.template"

aws cloudformation create-stack --region $region --stack-name $stack --capabilities CAPABILITY_IAM \
   --template-body file://$template \
   --parameters "[{\"ParameterKey\":\"AssignPublicIP\",\"ParameterValue\":\"${AssignPublicIP}\"},\
   {\"ParameterKey\":\"ESInstanceSize\",\"ParameterValue\":\"${ESInstanceSize}\"},\
   {\"ParameterKey\":\"HIDSInstanceQuantity\",\"ParameterValue\":\"${HIDSInstanceQuantity}\"},\
   {\"ParameterKey\":\"HIDSInstanceSize\",\"ParameterValue\":\"${HIDSInstanceSize}\"},\
   {\"ParameterKey\":\"MyS3Bucket\",\"ParameterValue\":\"${MyS3Bucket}\"},\
   {\"ParameterKey\":\"MyS3Key\",\"ParameterValue\":\"${MyS3Key}\"},\
   {\"ParameterKey\":\"MyTrustedNetwork\",\"ParameterValue\":\"${MyTrustedNetwork}\"},\
   {\"ParameterKey\":\"SubnetId\",\"ParameterValue\":\"${SubnetId}\"},\
   {\"ParameterKey\":\"VPCId\",\"ParameterValue\":\"${VPCId}\"},\
   {\"ParameterKey\":\"MyKeyPair\",\"ParameterValue\":\"${MyKeyPair}\"}]"
