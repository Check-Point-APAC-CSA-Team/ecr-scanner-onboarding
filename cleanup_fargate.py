import boto3
import time

# Initialize clients
ec2 = boto3.client('ec2', region_name='us-east-1')
ecr = boto3.client('ecr', region_name='us-east-1')
ecs = boto3.client('ecs', region_name='us-east-1')
iam = boto3.client('iam', region_name='us-east-1')
autoscaling = boto3.client('autoscaling', region_name='us-east-1')

# Function to delete the ECS cluster
def delete_ecs_cluster(cluster_name):
    try:
        ecs.update_cluster_settings(
            cluster=cluster_name,
            settings=[{'name': 'containerInsights', 'value': 'disabled'}]
        )
        ecs.delete_cluster(cluster=cluster_name)
        print(f"Deleted ECS Cluster: {cluster_name}")
    except Exception as e:
        print(f"Error deleting ECS Cluster: {e}")

# Function to delete the ECR repository
def delete_ecr_repository(repo_name):
    try:
        ecr.delete_repository(repositoryName=repo_name, force=True)
        print(f"Deleted ECR Repository: {repo_name}")
    except Exception as e:
        print(f"Error deleting ECR Repository: {e}")

# Function to detach and delete IAM role
def delete_iam_role(role_name):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn='arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy')
        iam.delete_role(RoleName=role_name)
        print(f"Deleted IAM Role: {role_name}")
    except Exception as e:
        print(f"Error deleting IAM Role: {e}")

# Function to delete the IAM instance profile
def delete_iam_instance_profile(profile_name, role_name):
    try:
        iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
        iam.delete_instance_profile(InstanceProfileName=profile_name)
        print(f"Deleted IAM Instance Profile: {profile_name}")
    except Exception as e:
        print(f"Error deleting IAM Instance Profile: {e}")

# Function to delete security groups
def delete_security_group(sg_id):
    try:
        ec2.delete_security_group(GroupId=sg_id)
        print(f"Deleted Security Group: {sg_id}")
    except Exception as e:
        print(f"Error deleting Security Group: {e}")

# Function to delete route table
def delete_route_table(route_table_id, subnet_id):
    try:
        ec2.disassociate_route_table(AssociationId=route_table_id)
        ec2.delete_route_table(RouteTableId=route_table_id)
        print(f"Deleted Route Table: {route_table_id}")
    except Exception as e:
        print(f"Error deleting Route Table: {e}")

# Function to delete internet gateway
def delete_internet_gateway(igw_id, vpc_id):
    try:
        ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        ec2.delete_internet_gateway(InternetGatewayId=igw_id)
        print(f"Deleted Internet Gateway: {igw_id}")
    except Exception as e:
        print(f"Error deleting Internet Gateway: {e}")

# Function to delete subnets
def delete_subnet(subnet_id):
    try:
        ec2.delete_subnet(SubnetId=subnet_id)
        print(f"Deleted Subnet: {subnet_id}")
    except Exception as e:
        print(f"Error deleting Subnet: {e}")

# Function to delete VPC
def delete_vpc(vpc_id):
    try:
        ec2.delete_vpc(VpcId=vpc_id)
        print(f"Deleted VPC: {vpc_id}")
    except Exception as e:
        print(f"Error deleting VPC: {e}")

# Clean up ECS clusters
clusters = ecs.list_clusters()['clusterArns']
for cluster in clusters:
    if 'unique-ecs-cluster-' in cluster:
        cluster_name = cluster.split('/')[-1]
        delete_ecs_cluster(cluster_name)

# Clean up ECR repositories
repositories = ecr.describe_repositories()['repositories']
for repo in repositories:
    if 'unique-ecr-repo-' in repo['repositoryName']:
        delete_ecr_repository(repo['repositoryName'])

# Clean up IAM roles and instance profiles
roles = iam.list_roles()['Roles']
for role in roles:
    if 'unique-ecsTaskRole-' in role['RoleName']:
        delete_iam_role(role['RoleName'])

instance_profiles = iam.list_instance_profiles()['InstanceProfiles']
for profile in instance_profiles:
    if 'ecsInstanceProfile' in profile['InstanceProfileName']:
        delete_iam_instance_profile(profile['InstanceProfileName'], role['RoleName'])

# Clean up EC2 resources
vpcs = ec2.describe_vpcs()['Vpcs']
for vpc in vpcs:
    if '10.0.0.0/16' in vpc['CidrBlock']:
        vpc_id = vpc['VpcId']
        # Clean up security groups
        security_groups = ec2.describe_security_groups(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['SecurityGroups']
        for sg in security_groups:
            if 'unique-ecs-sg-' in sg['GroupName']:
                delete_security_group(sg['GroupId'])
        
        # Clean up route tables
        route_tables = ec2.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['RouteTables']
        for rt in route_tables:
            if 'rtb-' in rt['RouteTableId']:
                delete_route_table(rt['RouteTableId'], vpc_id)
        
        # Clean up internet gateways
        internet_gateways = ec2.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])['InternetGateways']
        for igw in internet_gateways:
            delete_internet_gateway(igw['InternetGatewayId'], vpc_id)
        
        # Clean up subnets
        subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['Subnets']
        for subnet in subnets:
            delete_subnet(subnet['SubnetId'])
        
        # Finally, delete the VPC
        delete_vpc(vpc_id)

