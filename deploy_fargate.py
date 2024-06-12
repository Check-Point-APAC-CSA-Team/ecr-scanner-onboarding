import boto3
import base64
import json
import os
import time
from datetime import datetime

# Initialize clients
ec2 = boto3.client('ec2', region_name='us-east-1')
ecr = boto3.client('ecr', region_name='us-east-1')
ecs = boto3.client('ecs', region_name='us-east-1')
iam = boto3.client('iam', region_name='us-east-1')

# Variables
account_id = '471112983433'
region = 'us-east-1'
timestamp = datetime.now().strftime('%Y%m%d%H%M%S')

# Step 1: Create a new VPC
response = ec2.create_vpc(
    CidrBlock='10.0.0.0/16'
)
vpc_id = response['Vpc']['VpcId']
print(f"Created VPC: {vpc_id}")

ec2.modify_vpc_attribute(
    VpcId=vpc_id,
    EnableDnsSupport={'Value': True}
)
ec2.modify_vpc_attribute(
    VpcId=vpc_id,
    EnableDnsHostnames={'Value': True}
)

# Step 2: Create a subnet
response = ec2.create_subnet(
    VpcId=vpc_id,
    CidrBlock='10.0.1.0/24'
)
subnet_id = response['Subnet']['SubnetId']
print(f"Created Subnet: {subnet_id}")

# Step 3: Create an internet gateway and attach it to the VPC
response = ec2.create_internet_gateway()
internet_gateway_id = response['InternetGateway']['InternetGatewayId']
print(f"Created Internet Gateway: {internet_gateway_id}")

ec2.attach_internet_gateway(
    InternetGatewayId=internet_gateway_id,
    VpcId=vpc_id
)

# Step 4: Create a route table and a route to the internet gateway
response = ec2.create_route_table(
    VpcId=vpc_id
)
route_table_id = response['RouteTable']['RouteTableId']
print(f"Created Route Table: {route_table_id}")

ec2.create_route(
    RouteTableId=route_table_id,
    DestinationCidrBlock='0.0.0.0/0',
    GatewayId=internet_gateway_id
)

ec2.associate_route_table(
    RouteTableId=route_table_id,
    SubnetId=subnet_id
)

# Step 5: Create a new security group
response = ec2.create_security_group(
    GroupName=f'unique-ecs-sg-{timestamp}',
    Description='Security group for ECS cluster',
    VpcId=vpc_id
)
security_group_id = response['GroupId']
print(f"Created Security Group: {security_group_id}")

# Step 6: Add inbound rules to the security group
ec2.authorize_security_group_ingress(
    GroupId=security_group_id,
    IpPermissions=[
        {
            'IpProtocol': 'tcp',
            'FromPort': 80,
            'ToPort': 80,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        },
        {
            'IpProtocol': 'tcp',
            'FromPort': 443,
            'ToPort': 443,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        }
    ]
)
print("Added inbound rules to the Security Group")

# Step 7: Create an ECR repository
response = ecr.create_repository(
    repositoryName=f'unique-ecr-repo-{timestamp}'
)
repository_uri = response['repository']['repositoryUri']
print(f"Created ECR Repository: {repository_uri}")

# Step 8: Create an ECS cluster
response = ecs.create_cluster(
    clusterName=f'unique-ecs-cluster-{timestamp}'
)
cluster_name = response['cluster']['clusterName']
print(f"Created ECS Cluster: {response['cluster']['clusterArn']}")

# Step 9: Create an IAM role for ECS tasks
trust_relationship = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ecs-tasks.amazonaws.com"
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

iam.attach_role_policy(
    RoleName=f'unique-ecsTaskRole-{timestamp}',
    PolicyArn='arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy'
)
print("Attached policy to IAM Role")

# Step 10: Build and push a simple Docker image to the ECR
# (Assuming Docker is installed and configured on your machine)
dockerfile_content = """
FROM alpine:latest
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

# Step 11: Create a task definition and run the ECS task using Fargate
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

# Step 12: Run the ECS task using Fargate
response = ecs.run_task(
    cluster=cluster_name,
    launchType='FARGATE',
    taskDefinition=f'unique-task-{timestamp}',
    networkConfiguration={
        'awsvpcConfiguration': {
            'subnets': [subnet_id],
            'securityGroups': [security_group_id],
            'assignPublicIp': 'ENABLED'
        }
    }
)
print(f"Started ECS Task: {response['tasks'][0]['taskArn']}")

