import boto3
import base64
import json
import os
import time
from datetime import datetime

# Initialize clients
ec2 = boto3.client('ec2', region_name='ap-east-1')
ecr = boto3.client('ecr', region_name='ap-east-1')
ecs = boto3.client('ecs', region_name='ap-east-1')
iam = boto3.client('iam', region_name='ap-east-1')
autoscaling = boto3.client('autoscaling', region_name='ap-east-1')

# Variables
account_id = '533267110973'
region = 'ap-east-1'
timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
ssh_public_key = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCWGhIY7tobKGnr3CyTlBQ2tOD1k9Bd3j6s/QqqhELxZ21AyqRmC1x2T7u0CuxB/tYLBvM/SJ8Vb5rs5u2+Du0EyLuwvl9yPQVVD3DOuO3IZzCs/eVNn9/NBK772576oaqGrs0r7LF+lncZHzDUCTU+W+h6iMs2BWdp/ZispAsMVPPdApfAJnHCB2H7jYv7sluoI2i/GnynOpSBr+iqqJRb2eUepDBrjhNpEwvV5Zst8jSSRVp38+RyBtELAmypaW9KoAHTjjW+e2X5MWskFW3+BuTn7d+UREEYremMCO5Kr/qVdqI+NAjPuXzmPyJ02QcHupoxBsdWRPRZgljIOvMD rsa-key-20220929'

# Step 1: Create a new VPC
response = ec2.create_vpc(CidrBlock='10.0.0.0/16')
vpc_id = response['Vpc']['VpcId']
print(f"Created VPC: {vpc_id}")

ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={'Value': True})
ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={'Value': True})

# Step 2: Create a subnet
response = ec2.create_subnet(VpcId=vpc_id, CidrBlock='10.0.1.0/24')
subnet_id = response['Subnet']['SubnetId']
print(f"Created Subnet: {subnet_id}")

# Enable auto-assign public IP on subnet
ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={'Value': True})

# Step 3: Create an internet gateway and attach it to the VPC
response = ec2.create_internet_gateway()
internet_gateway_id = response['InternetGateway']['InternetGatewayId']
print(f"Created Internet Gateway: {internet_gateway_id}")

ec2.attach_internet_gateway(InternetGatewayId=internet_gateway_id, VpcId=vpc_id)

# Step 4: Create a route table and a route to the internet gateway
response = ec2.create_route_table(VpcId=vpc_id)
route_table_id = response['RouteTable']['RouteTableId']
print(f"Created Route Table: {route_table_id}")

ec2.create_route(RouteTableId=route_table_id, DestinationCidrBlock='0.0.0.0/0', GatewayId=internet_gateway_id)
ec2.associate_route_table(RouteTableId=route_table_id, SubnetId=subnet_id)

# Step 5: Create a new security group
response = ec2.create_security_group(GroupName=f'unique-ecs-sg-{timestamp}', Description='Security group for ECS cluster', VpcId=vpc_id)
security_group_id = response['GroupId']
print(f"Created Security Group: {security_group_id}")

# Step 6: Add inbound rules to the security group
ec2.authorize_security_group_ingress(
    GroupId=security_group_id,
    IpPermissions=[
        {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
        {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
        {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
    ]
)
print("Added inbound rules to the Security Group")

# Step 7: Create an ECR repository
response = ecr.create_repository(repositoryName=f'unique-ecr-repo-{timestamp}')
repository_uri = response['repository']['repositoryUri']
print(f"Created ECR Repository: {repository_uri}")

# Step 8: Create an ECS cluster
response = ecs.create_cluster(clusterName=f'unique-ecs-cluster-{timestamp}')
cluster_name = response['cluster']['clusterName']
print(f"Created ECS Cluster: {response['cluster']['clusterArn']}")

# Step 9: Create an IAM role for ECS tasks
trust_relationship = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": ["ecs.amazonaws.com", "ec2.amazonaws.com", "ecs-tasks.amazonaws.com"]
            },
            "Action": "sts:AssumeRole"
        }
    ]
}

response = iam.create_role(
    RoleName=f'unique-ecsTaskRole-{timestamp}',
    AssumeRolePolicyDocument=json.dumps(trust_relationship)
)
role_arn = response['Role']['Arn']
print(f"Created IAM Role: {role_arn}")

# Attach the specified policies to the role
policy_document = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecs:CreateCluster",
                "ecs:DeregisterContainerInstance",
                "ecs:DiscoverPollEndpoint",
                "ecs:Poll",
                "ecs:RegisterContainerInstance",
                "ecs:StartTelemetrySession",
                "ecs:Submit*",
                "ecs:StartTask",
                "ecs:RunTask",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchCheckLayerAvailability",
                "ecr:BatchDeleteImage",
                "ecr:BatchGetImage",
                "ecr:CompleteLayerUpload",
                "ecr:CreateRepository",
                "ecr:DeleteLifecyclePolicy",
                "ecr:DeleteRepository",
                "ecr:DeleteRepositoryPolicy",
                "ecr:DescribeImages",
                "ecr:DescribeRepositories",
                "ecr:GetAuthorizationToken",
                "ecr:GetDownloadUrlForLayer",
                "ecr:GetLifecyclePolicy",
                "ecr:GetLifecyclePolicyPreview",
                "ecr:GetRepositoryPolicy",
                "ecr:InitiateLayerUpload",
                "ecr:ListImages",
                "ecr:ListTagsForResource",
                "ecr:PutImage",
                "ecr:PutLifecyclePolicy",
                "ecr:SetRepositoryPolicy",
                "ecr:TagResource",
                "ecr:UntagResource",
                "ecr:UploadLayerPart",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "*"
        }
    ]
}

iam.put_role_policy(
    RoleName=f'unique-ecsTaskRole-{timestamp}',
    PolicyName='ECSExecutionRolePolicy',
    PolicyDocument=json.dumps(policy_document)
)
print("Attached specified policy to IAM Role")

# Step 10: Create an IAM instance profile and add the role
instance_profile_name = f'unique-ecs-instance-profile-{timestamp}'
iam.create_instance_profile(InstanceProfileName=instance_profile_name)
iam.add_role_to_instance_profile(InstanceProfileName=instance_profile_name, RoleName=f'unique-ecsTaskRole-{timestamp}')
print("Created IAM Instance Profile and added the role")

# Step 11: Build and push a simple Docker image to the ECR
dockerfile_content = """
FROM alpine:latest
RUN apk add --no-cache curl
CMD ["echo", "Hello from unique-ecs-task!"]
"""

with open('Dockerfile', 'w') as f:
    f.write(dockerfile_content)

os.system(f'docker build -t unique-ecr-repo-{timestamp} .')

# ECR login
login_command = f'aws ecr get-login-password --region {region} | docker login --username AWS --password-stdin {account_id}.dkr.ecr.{region}.amazonaws.com'
login_status = os.system(login_command)
if login_status != 0:
    raise Exception("Failed to login to ECR")

os.system(f'docker tag unique-ecr-repo-{timestamp}:latest {repository_uri}:latest')
os.system(f'docker push {repository_uri}:latest')

# Step 12: Find the latest ECS-optimized AMI
response = ec2.describe_images(
    Owners=['amazon'],
    Filters=[
        {'Name': 'name', 'Values': ['amzn2-ami-ecs-hvm-*-x86_64-ebs']}
    ]
)
latest_image = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)[0]
ami_id = latest_image['ImageId']
print(f"Found latest ECS-optimized AMI: {ami_id}")

# Step 13: Create a launch template
user_data = base64.b64encode(f'''#!/bin/bash
echo ECS_CLUSTER={cluster_name} >> /etc/ecs/ecs.config
echo ECS_DATADIR=/data >> /etc/ecs/ecs.config
echo ECS_ENABLE_TASK_IAM_ROLE=true >> /etc/ecs/ecs.config
echo ECS_ENABLE_TASK_IAM_ROLE_NETWORK_HOST=true >> /etc/ecs/ecs.config
echo ECS_LOGFILE=/log/ecs-agent.log >> /etc/ecs/ecs.config
echo ECS_AVAILABLE_LOGGING_DRIVERS=["json-file","awslogs"] >> /etc/ecs/ecs.config
echo ECS_LOGLEVEL=info >> /etc/ecs/ecs.config
echo {ssh_public_key} >> /home/ec2-user/.ssh/authorized_keys
'''.encode('utf-8')).decode('utf-8')

response = ec2.create_launch_template(
    LaunchTemplateName=f'unique-ecs-launch-template-{timestamp}',
    VersionDescription="Initial version",
    LaunchTemplateData={
        'ImageId': ami_id,
        'InstanceType': 't2.micro',
        'IamInstanceProfile': {'Name': instance_profile_name},
        'UserData': user_data,
        'SecurityGroupIds': [security_group_id]
    }
)
launch_template_id = response['LaunchTemplate']['LaunchTemplateId']
print(f"Created Launch Template: {launch_template_id}")

# Step 14: Create an Auto Scaling group
response = autoscaling.create_auto_scaling_group(
    AutoScalingGroupName=f'unique-ecs-asg-{timestamp}',
    LaunchTemplate={
        'LaunchTemplateId': launch_template_id,
        'Version': '$Latest'
    },
    MinSize=1,
    MaxSize=1,
    DesiredCapacity=1,
    VPCZoneIdentifier=subnet_id
)
print("Created Auto Scaling Group")

# Step 15: Wait for the instance to be running and registered with the ECS cluster
timeout = time.time() + 60*10  # 10 minutes timeout
instance_id = None
while time.time() < timeout:
    response = ec2.describe_instances(Filters=[
        {'Name': 'instance-state-name', 'Values': ['running']},
        {'Name': 'tag:aws:autoscaling:groupName', 'Values': [f'unique-ecs-asg-{timestamp}']}
    ])
    if 'Reservations' in response and len(response['Reservations']) > 0:
        instances = response['Reservations'][0]['Instances']
        if len(instances) > 0:
            instance_id = instances[0]['InstanceId']
            print(f"Found EC2 instance IDs: {[instance_id]}")
            break
    time.sleep(15)

if not instance_id:
    raise Exception("Timeout: EC2 instance did not start in time")

# Ensure instance is in running state
instance_running = False
while time.time() < timeout:
    response = ec2.describe_instance_status(InstanceIds=[instance_id])
    instance_statuses = response.get('InstanceStatuses', [])
    instance_states = {status['InstanceId']: status['InstanceState']['Name'] for status in instance_statuses}
    print(f"Instance states: {instance_states}")
    if instance_states.get(instance_id) == 'running':
        instance_running = True
        break
    time.sleep(15)

if not instance_running:
    raise Exception("Timeout: EC2 instance did not reach running state in time")

# Verify ECS agent registration
ecs_registered = False
while time.time() < timeout:
    response = ecs.list_container_instances(cluster=cluster_name)
    if len(response['containerInstanceArns']) > 0:
        ecs_registered = True
        break
    time.sleep(15)

if not ecs_registered:
    console_output = ec2.get_console_output(InstanceId=instance_id, Latest=True)
    print(console_output['Output'])
    raise Exception("Timeout: EC2 instance did not register with the cluster in time")

# Step 16: Create a task definition and run the ECS task using EC2 launch type
task_definition = {
    "family": f'unique-task-{timestamp}',
    "executionRoleArn": role_arn,
    "networkMode": "awsvpc",
    "containerDefinitions": [
        {
            "name": "unique-container",
            "image": f"{repository_uri}:latest",
            "memory": 512,
            "cpu": 256,
            "essential": True
        }
    ],
    "requiresCompatibilities": ["EC2"],
    "cpu": "256",
    "memory": "512"
}

response = ecs.register_task_definition(**task_definition)
print(f"Registered Task Definition: {response['taskDefinition']['taskDefinitionArn']}")

response = ecs.run_task(
    cluster=cluster_name,
    launchType='EC2',
    taskDefinition=f'unique-task-{timestamp}',
    networkConfiguration={
        'awsvpcConfiguration': {
            'subnets': [subnet_id],
            'securityGroups': [security_group_id]
        }
    }
)
print(f"Started ECS Task: {response['tasks'][0]['taskArn']}")

# Step 17: Login to Quay, pull the image, and push it to the ECR repository
os.system('echo "64DILXL1OVTI9O7ZXVPVBV9703XVCS4210UIKLPSBYM2ES0PLSENPDCMKZF1V62S" | docker login quay.io -u checkpoint+public_access --password-stdin')
os.system('docker pull quay.io/checkpoint/consec-imagescan-engine:2.28.0')
os.system(f'docker tag quay.io/checkpoint/consec-imagescan-engine:2.28.0 {repository_uri}:consec-imagescan-engine-2.28.0')
os.system(f'docker push {repository_uri}:consec-imagescan-engine-2.28.0')
print("Pulled image from Quay and pushed to ECR")
