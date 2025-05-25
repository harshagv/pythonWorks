#!/bin/bash

CID=$1
PORT=5000

if [ -z "$CID" ]; then
  echo "Usage: $0 <enclave_cid>"
  exit 1
fi

echo "Parent: Connecting to enclave CID=$CID port=$PORT..."
RESPONSE=$(socat - VSOCK-CONNECT:$CID:$PORT)

if [ -z "$RESPONSE" ]; then
  echo "Parent: No response from agent."
  exit 1
fi

echo "Parent: Received response:"
echo "$RESPONSE"

# Optional: Compute SHA256 hash
HASH=$(echo "$RESPONSE" | sha256sum | awk '{print $1}')
echo "Parent: SHA256 Hash: $HASH"

# Attestation fabric submission
# # Extract $RESPONSE fields
RECORD_ID="$(echo "$RESPONSE" | jq -r '.timestamp')_$(echo "$RESPONSE" | jq -r '.agentID')"
HASH=$(echo "$RESPONSE" | sha256sum | awk '{print $1}')
SIGNATURE=$(echo "$RESPONSE" | jq -r '.attestation.dummy_attestation')
TIMESTAMP=$(echo "$RESPONSE" | jq -r '.timestamp')
AGENT_ID=$(echo "$RESPONSE" | jq -r '.agentID')

echo "Submitting $RECORD_ID to Fabric..."

# Adjust these to your actual setup
ORDERER_TLS_CA="${PWD}/fabric-samples/test-network/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
PEER0_ORG1_TLS="${PWD}/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
PEER0_ORG2_TLS="${PWD}/fabric-samples/test-network/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"

peer chaincode invoke \
  -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com \
  --tls \
  --cafile "$ORDERER_TLS_CA" \
  -C mychannel \
  -n attestation \
  -c "{\"Args\":[\"StoreAttestation\",\"$RECORD_ID\",\"$HASH\",\"$SIGNATURE\",\"$TIMESTAMP\",\"$AGENT_ID\"]}" \
  --peerAddresses localhost:7051 \
  --tlsRootCertFiles "$PEER0_ORG1_TLS" \
  --peerAddresses localhost:9051 \
  --tlsRootCertFiles "$PEER0_ORG2_TLS"

if [ $? -eq 0 ]; then
  echo "✅ Fabric submission successful."
else
  echo "❌ Fabric submission failed."
fi