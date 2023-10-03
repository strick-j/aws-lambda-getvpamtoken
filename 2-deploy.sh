#!/bin/bash
set -eo pipefail
ARTIFACT_BUCKET=$(cat bucket-name.txt)
cd function
GOOS=linux go build main.go
cd ../
sam package --template-file template.yml --output-template-file out.yml --s3-bucket $ARTIFACT_BUCKET
sam deploy --template-file out.yml --stack-name aws-lambda-getvpamtoken --capabilities CAPABILITY_NAMED_IAM --config-env default