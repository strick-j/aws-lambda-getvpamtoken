#!/bin/bash
set -eo pipefail
STACK=aws-lambda-getvpamtoken
RESTAPIID=$(aws cloudformation describe-stack-resource --stack-name $STACK --logical-resource-id CybrTokenGateway --query 'StackResourceDetail.PhysicalResourceId' --output text)
RESOURCEID=$(aws apigateway get-resources --rest-api-id $RESTAPIID --query "items[?(pathPart=='token')].id" --output text)
while true; do
  aws apigateway test-invoke-method --rest-api-id $RESTAPIID --resource-id $RESOURCEID --http-method GET
  echo ""
  sleep 2
done