# aws-lambda-getvpamtoken
Lambda function that allows programatic retrieval of jwt creation to access CyberArk Vendor PAM or CyberArk Secure Web Sessions API.

## Utilization
1. Copy the repo:
```
git clone https://
```
2. Modify the samlconfig.toml file. Specifically update the parameter_overrides line. An example valid entry is below. Note that the Key Value Pairs are seperated by a space:
```
parameter_overrides = "CybrKey=arn:aws:secretsmanager:us-east-2:123452532524:secret:SecretName-1P8Whs CybrTenantId=11ed307a252bbd10987ef76ae4e0982d CybrServiceAccountId=11ed307a252bbd10987ef76ae4e0982d CybrRegion=us"
```
3. Make the bash scripts executable
```
chmod +x *.sh
```
4. Execute the scripts in the appropriate order. 

### Script Details
1. 0-run-tests.sh - Runs GO tests for main.go
2. 1-create-bucket.sh - Creates bucket which will be utilized for uploading the Lambda function
3. 2-deploy.sh - Uses the SAM CLI to package and deploy the Lambda function, API Gateway, and associated roles required for the Lambda function
4. 3-invoke.sh - Invokes the API Gateway using `aws apigateway test-invoke-method`
5. 4-cleanup.sh - Removes the AWS resources and prompts for removal of the S3 Bucket and logs created previously

## Requirements
1. Prior to using the scripts you should have already installed and configured the your AWS CLI and AWS SAM CLI
2. Prior to using the scripts you should have already installed GO

