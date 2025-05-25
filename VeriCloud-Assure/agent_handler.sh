#!/bin/sh

BUCKET="cf-templates-wwo0kbjh3nnq-us-east-2"
echo "Agent: Received connection for S3 bucket: $BUCKET" >&2

# Get S3 encryption status
if aws s3api get-bucket-encryption --bucket "$BUCKET" >/dev/null 2>&1; then
  encryption_status="Enabled"
else
  encryption_status="NotEnabled"
fi

# Get S3 public access block settings
public_block=$(aws s3api get-public-access-block --bucket "$BUCKET" 2>/dev/null)
if echo "$public_block" | grep -q '"BlockPublicAcls": *true' && \
   echo "$public_block" | grep -q '"IgnorePublicAcls": *true' && \
   echo "$public_block" | grep -q '"BlockPublicPolicy": *true' && \
   echo "$public_block" | grep -q '"RestrictPublicBuckets": *true'; then
  is_public="Private"
else
  is_public="PotentiallyPublic"
fi

# Check bucket policy status
bucket_policy_status=$(aws s3api get-bucket-policy-status --bucket "$BUCKET" 2>/dev/null)
if echo "$bucket_policy_status" | grep -q '"IsPublic": *true'; then
  policy_status="Public"
else
  policy_status="Private"
fi

# Output results to stderr for logs
echo "Encryption Status: $encryption_status" >&2
echo "Policy-based Public Access: $policy_status" >&2

# Fake attestation (can be replaced with real attestation data later)
ATTESTATION_SIG="dummy_attestation_$(date +%s)"

# Current UTC timestamp
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Emit JSON to stdout
cat <<EOF
{
  "check_result": {
    "bucket": "$BUCKET",
    "encryption": "$encryption_status",
    "public_access": "$is_public",
    "bucket_policy_status": "$policy_status"
  },
  "attestation": {
    "dummy_attestation": "$ATTESTATION_SIG"
  },
  "timestamp": "$TIMESTAMP",
  "agentID": "agent_default"
}
EOF
# End of script