# CHECK instance type
```bash
curl -H "X-aws-ec2-metadata-token: $(curl -sX PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')" http://169.254.169.254/latest/meta-data/instance-type

curl -H "X-aws-ec2-metadata-token: $(curl -sX PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')" http://169.254.169.254/latest/dynamic/instance-identity/document
```

# CHECK if Nitro Enclaves is ENABLED
```bash
curl -H "X-aws-ec2-metadata-token: $(curl -sX PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')" http://169.254.169.254/latest/meta-data/nitro-enclaves
```

# Build the gvh-repo/enclave-agent container
```bash
docker build -t gvh-repo/enclave-agent . -f Dockerfile.enclave
```

# Build the EIF
```bash
nitro-cli build-enclave --docker-uri gvh-repo/enclave-agent:latest --output-file enclave_agent.eif
```

# Launch the Enclave on Parent EC2 Instance
```bash
nitro-cli run-enclave --cpu-count 2 --memory 512 --eif-path enclave_agent.eif --enclave-cid 16 --debug-mode
```

# Check if enclave is running successfully
```bash
nitro-cli console --enclave-id $(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
```

# Start the parent_listener.sh 
```bash
bash parent_listener.sh <enclave-cid>
bash parent_listener.sh 16
```

# Deploying the Blockchain Network (Hyperledger Fabric)
```bash
curl -sSL https://raw.githubusercontent.com/hyperledger/fabric/master/scripts/bootstrap.sh | bash -s
# curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.0
export PATH=$PATH:$(pwd)/fabric-samples/bin
echo 'export PATH=$PATH:$(pwd)/fabric-samples/bin' >> ~/.bashrc
echo 'export FABRIC_CFG_PATH=${PWD}/fabric-samples/config' >> ~/.bashrc
source ~/.bashrc

cd fabric-samples/test-network
./network.sh up createChannel -c mychannel -ca
```

# Deploy Chaincode (chaincode/attestation/attestation.go):
```bash
cd ../chaincode/attestation
go mod init attestation
go mod tidy

export CCNAME=attestation
export CCPATH=../chaincode/attestation
export CCLANG=golang
export CCVERSION=1.0
export CCSEQUENCE=1

./network.sh deployCC -ccn attestation -ccp ../chaincode/attestation -ccl go -c mychannel -ccv 1.0 -ccs 1 -cci InitLedger

source scripts/envVar.sh
setGlobals 1

peer chaincode query -C mychannel -n attestation -c '{"Args":["QueryAttestation","ATT000"]}'

# Upgrade attestation.go
./network.sh deployCC -ccn attestation -ccp ../chaincode/attestation -ccl go -c mychannel -ccv 2.0 -ccs 2
```

# Test Chaincode

export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID="Org1MSP"

peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile ${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem -C mychannel -n attestation -c '{"Args":["StoreAttestation","attest1","hash123","sig456","ts789","agent001"]}' --peerAddresses localhost:7051 --tlsRootCertFiles ${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt --peerAddresses localhost:9051 --tlsRootCertFiles ${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt


# Check Chaincode Commit and Installation
peer lifecycle chaincode queryinstalled
peer lifecycle chaincode querycommitted -C mychannel

peer chaincode query -C mychannel -n attestation -c '{"Args":["QueryAttestation","attest1"]}'

# RECORD_ID = <timestamp>_<agentID>
peer chaincode query -C mychannel -n attestation -c '{"Args":["QueryAttestation","2025-05-24T23:03:40Z_agent_default"]}'

peer chaincode query -C mychannel -n attestation -c '{"Args":["QueryAllAttestations"]}' | jq

