import boto3
import base64
import json
import os
import time
from datetime import datetime

# Variables
region = 'ap-east-1'
account_id = '533267110973'
timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
ssh_public_key = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCWGhIY7tobKGnr3CyTlBQ2tOD1k9Bd3j6s/QqqhELxZ21AyqRmC1x2T7u0CuxB/tYLBvM/SJ8Vb5rs5u2+Du0EyLuwvl9yPQVVD3DOuO3IZzCs/eVNn9/NBK772576oaqGrs0r7LF+lncZHzDUCTU+W+h6iMs2BWdp/ZispAsMVPPdApfAJnHCB2H7jYv7sluoI2i/GnynOpSBr+iqqJRb2eUepDBrjhNpEwvV5Zst8jSSRVp38+RyBtELAmypaW9KoAHTjjW+e2X5MWskFW3+BuTn7d+UREEYremMCO5Kr/qVdqI+NAjPuXzmPyJ02QcHupoxBsdWRPRZgljIOvMD rsa-key-20220929'

# Predefined resources
vpc_id = 'vpc-044e991b7baa59b8d'
subnet_id = 'subnet-08b75cc6049a88ca0'
route_table_id = 'rtb-0f3e371c196d18532'
security_group_id = 'sg-0b0d363a9a5ead475'

# Initialize clients
ec2 = boto3.client('ec2', region_name=region)
ecr = boto3.client('ecr', region_name=region)
ecs = boto3.client('ecs', region_name=region)
iam = boto3.client('iam', region_name=region)
autoscaling = boto3.client('autoscaling', region_name=region)

# Step 1: Create an ECR repository
response = ecr.create_repository(repositoryName=f'unique-ecr-repo-{timestamp}')
repository_uri = response['repository']['repositoryUri']
print(f"Created ECR Repository: {repository_uri}")

# Step 2: Create an ECS cluster
response = ecs.create_cluster(clusterName=f'unique-ecs-cluster-{timestamp}')
cluster_name = response['cluster']['clusterName']
print(f"Created ECS Cluster: {response['cluster']['clusterArn']}")

# Step 3: Create an IAM role for ECS tasks
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

# Step 4: Create an IAM instance profile and add the role
instance_profile_name = f'unique-ecs-instance-profile-{timestamp}'
iam.create_instance_profile(InstanceProfileName=instance_profile_name)
iam.add_role_to_instance_profile(InstanceProfileName=instance_profile_name, RoleName=f'unique-ecsTaskRole-{timestamp}')
print("Created IAM Instance Profile and added the role")

# Step 5: Build and push a simple Docker image to the ECR
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
push_status = os.system(f'docker push {repository_uri}:latest')
if push_status != 0:
    raise Exception("Failed to push the Docker image to ECR")

# Step 6: Find the latest ECS-optimized AMI
response = ec2.describe_images(
    Owners=['amazon'],
    Filters=[
        {'Name': 'name', 'Values': ['amzn2-ami-ecs-hvm-*-x86_64-ebs']}
    ]
)
latest_image = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)[0]
ami_id = latest_image['ImageId']
print(f"Found latest ECS-optimized AMI: {ami_id}")

# Step 7: Create a task definition and run the ECS task using Fargate launch type
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

# Step 8: Login to Quay, pull the image, and push it to the ECR repository
quay_login_command = 'echo "64DILXL1OVTI9O7ZXVPVBV9703XVCS4210UIKLPSBYM2ES0PLSENPDCMKZF1V62S" | docker login quay.io -u checkpoint+public_access --password-stdin'
os.system(quay_login_command)
os.system('docker pull quay.io/checkpoint/consec-imagescan-engine:2.28.0')
os.system(f'docker tag quay.io/checkpoint/consec-imagescan-engine:2.28.0 {repository_uri}:consec-imagescan-engine-2.28.0')

# ECR login for second image push
login_status = os.system(login_command)
if login_status != 0:
    raise Exception("Failed to login to ECR for second image push")

push_status = os.system(f'docker push {repository_uri}:consec-imagescan-engine-2.28.0')
if push_status != 0:
    raise Exception("Failed to push the Quay image to ECR")

print("Pulled image from Quay and pushed to ECR")
