#!/bin/bash
set -eux

# Update system
yum update -y

# Install Docker (Amazon Linux 2)
yum install docker -y
# dnf update
# dnf install podman
# dnf install podman-docker
# dnf install procps-ng openssh-server net-tools iproute iptables-nft

# Install docker compose
# Download Docker Compose binary (replace version as needed)
curl -L "https://github.com/docker/compose/releases/download/v2.30.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose

service docker start
systemctl enable --now docker
usermod -aG docker ec2-user
#usermod -aG docker $USER

# Install additional packages
yum install -y vim wget git python3 python3-pip gcc gcc-c++ make openssl-devel

# Install Go (Amazon Linux 2 provides golang 1.20+ via extras)
yum install -y golang

# Install AWS CLI v2 (already present on new AL2 AMIs, but just in case)
yum install -y awscli
yum install socat jq -y

# Install Nitro Enclaves CLI and development tools
yum install aws-nitro-enclaves-cli -y
yum install -y aws-nitro-enclaves-cli-devel

# Add user to ne group (for Nitro Enclaves)
usermod -aG ne ec2-user

# Start Nitro Enclaves Allocator service
systemctl start nitro-enclaves-allocator.service
systemctl enable --now nitro-enclaves-allocator.service

cat > /etc/nitro_enclaves/allocator.yaml <<EOF
cpu_count: 2
memory_mib: 3072
# cpu_pool: 2,3,6-9
EOF

sudo systemctl restart nitro-enclaves-allocator.service

# Install Python packages
yum upgrade python3-pip -y
pip3 install --upgrade pip 
pip3 install boto3

# Print versions for verification
docker --version
docker-compose --version
go version
git --version
python3 --version
aws --version
nitro-cli --version
