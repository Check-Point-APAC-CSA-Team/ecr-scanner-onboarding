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
# ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={'Value': True})

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

# Skip the steps related to EC2, Launch Template, and Auto Scaling group
# Step 13: Create a task definition and run the ECS task using Fargate launch type
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
    "requiresCompatibilities": ["FARGATE"],
    "cpu": "256",
    "memory": "512"
}

response = ecs.register_task_definition(**task_definition)
print(f"Registered Task Definition: {response['taskDefinition']['taskDefinitionArn']}")

response = ecs.run_task(
    cluster=cluster_name,
    launchType='FARGATE',
    taskDefinition=f'unique-task-{timestamp}',
    networkConfiguration={
        'awsvpcConfiguration': {
            'subnets': [subnet_id],
            'securityGroups': [security_group_id],
            'assignPublicIp': 'DISABLED'
        }
    }
)
print(f"Started ECS Task: {response['tasks'][0]['taskArn']}")

# Step 14: Login to Quay, pull the image, and push it to the ECR repository
os.system('echo "64DILXL1OVTI9O7ZXVPVBV9703XVCS4210UIKLPSBYM2ES0PLSENPDCMKZF1V62S" | docker login quay.io -u checkpoint+public_access --password-stdin')
os.system('docker pull quay.io/checkpoint/consec-imagescan-engine:2.28.0')
os.system(f'docker tag quay.io/checkpoint/consec-imagescan-engine:2.28.0 {repository_uri}:consec-imagescan-engine-2.28.0')
os.system(f'docker push {repository_uri}:consec-imagescan-engine-2.28.0')
print("Pulled image from Quay and pushed to ECR")
