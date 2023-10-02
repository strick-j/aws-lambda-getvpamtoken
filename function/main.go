package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/rand"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	runtime "github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
	"github.com/golang-jwt/jwt"
)

var (
	conf *Config
	err  error
)

var getKey = checkPrivateKey

type Config struct {
	SecretsManager secretsmanageriface.SecretsManagerAPI
}

func InitializeConfig() (*Config, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(os.Getenv("AWS_REGION"))},
	)
	if err != nil {
		return &Config{}, fmt.Errorf("unable to create session to aws: %v", err)
	}
	return &Config{
		SecretsManager: secretsmanager.New(sess),
	}, nil
}

func init() {
	conf, err = InitializeConfig()
	if err != nil {
		log.Fatalf("Unable to initialize config: %v", err)
	}
	rand.New(rand.NewSource(time.Now().UnixNano()))
}

// Generates a random sequency of numbers to utlize
// for the 'jti' portion of the jwt
func randSeq(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// Checks for Tenant Id and validates if it is 32 charachters
// including lowercase letters and numbers
func checkTenant() (*string, error) {
	tenantId := os.Getenv("CYBR_TENANT_ID")
	if len(tenantId) == 0 {
		err := fmt.Errorf("checkTenant: no Tenant ID set in environment variables")
		return nil, err
	}
	check := regexp.MustCompile("^([a-z0-9]{32})$")
	if !check.MatchString(strings.ToLower(tenantId)) {
		err := fmt.Errorf("checkTenant: Invalid Tenant ID provided: %v", tenantId)
		return nil, err
	}
	corTenantId := strings.ToLower(tenantId)
	return &corTenantId, nil
}

// Checks for Sevice Account Id and validates if it is 32 charachters
// including lowercase letters and numbers
func checkServiceAccount() (*string, error) {
	serviceAccountId := os.Getenv("CYBR_SERVICE_ACCOUNT_ID")
	if len(serviceAccountId) == 0 {
		err := fmt.Errorf("checkTenant: no Tenant ID set in environment variables")
		return nil, err
	}
	check := regexp.MustCompile("^([a-z0-9]{32})$")
	if !check.MatchString(strings.ToLower(serviceAccountId)) {
		err := fmt.Errorf("checkTenant: Invalid Tenant ID provided: %v", serviceAccountId)
		return nil, err
	}
	corServiceAccountId := strings.ToLower(serviceAccountId)
	return &corServiceAccountId, nil
}

// Checks provided region and validates it is an approved region
func checkRegion() (*string, error) {
	region := os.Getenv("CYBR_REGION")
	if len(region) == 0 {
		err := fmt.Errorf("checkRegion: no region set in environment variables")
		return nil, err
	}
	audurl := map[string]string{
		"us":        "https://auth.alero.io/auth/realms/serviceaccounts",
		"eu":        "https://auth.alero.eu/auth/realms/serviceaccounts",
		"canada":    "https://auth.ca.alero.io/auth/realms/serviceaccounts",
		"austraila": "https://auth.au.alero.io/auth/realms/serviceaccounts",
		"london":    "https://auth.uk.alero.io/auth/realms/serviceaccounts",
		"india":     "https://auth.in.alero.io/auth/realms/serviceaccounts",
		"singapore": "https://auth.sg.alero.io/auth/realms/serviceaccounts",
	}
	var u interface{} = audurl
	audience := u.(map[string]string)[strings.ToLower(region)]
	if len(audience) == 0 {
		err := fmt.Errorf("checkRegion: Invalid region provided: %v. Valid regions are: US, EU, Canada, Austraila, London, India, and Singapore", region)
		return nil, err
	}
	return &audience, nil
}

// Checks Private Kay and validates it is the correct type
func checkPrivateKey() (*rsa.PrivateKey, error) {
	// Create struct to hold private key
	var secretData struct {
		Address    string `json:"address"`
		Username   string `json:"username"`
		Platformid string `json:"platformid"`
		Password   string `json:"password"`
		Comment    string `json:"comment"`
	}
	// Get private key from Secrets Manager
	result, err := conf.SecretsManager.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(os.Getenv("CYBR_KEY")),
		VersionStage: aws.String("AWSCURRENT"),
	})
	if err != nil {
		return nil, fmt.Errorf("checkPrivateKey: %v", err)
	}
	var secretString string
	if result != nil {
		secretString = *result.SecretString
	}
	// Convert private key to string
	err = json.Unmarshal([]byte(secretString), &secretData)
	if err != nil {
		return nil, fmt.Errorf("checkPrivateKey: %v", err)
	}
	// Decode private key
	privateKey, err := base64.StdEncoding.DecodeString(secretData.Password)
	if err != nil {
		return nil, fmt.Errorf("checkPrivateKey: %v", err)
	}
	// Make sure private key is not empty
	if len(privateKey) == 0 {
		err := fmt.Errorf("checkPrivateKey: no Private Key set in environment variables")
		return nil, err
	}
	pemString := strings.TrimSpace(string(privateKey))
	// Make sure private key is PEM encoded
	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		return nil, fmt.Errorf("checkPrivateKey: unable to decode Private Key, Private Key: %v", pemString)
	}
	// Make sure private key is RSA
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("checkPrivateKey: %v", err)
	}
	return key, err
}

func callLambda() (*string, error) {
	// Validate Tenant ID
	tenantid, err := checkTenant()
	if err != nil {
		return nil, err
	}
	// Validate Tenant ID
	serviceaccountid, err := checkServiceAccount()
	if err != nil {
		return nil, err
	}
	// Validate Region
	audience, err := checkRegion()
	if err != nil {
		return nil, err
	}
	// Validate Private Key
	key, err := getKey()
	if err != nil {
		return nil, err
	}
	str := []string{*tenantid, *serviceaccountid, "ExternalServiceAccount"}
	s := strings.Join(str, ".")

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": s,
		"sub": s,
		"aud": audience,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Duration(5) * time.Minute).Unix(),
		"jti": randSeq(20),
	})

	tokenString, err := token.SignedString(key)
	if err != nil {
		fmt.Printf("Error: %v", err)
		return nil, err
	}
	return &tokenString, nil
}

func handleRequest(ctx context.Context, event events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var ApiResponse events.APIGatewayProxyResponse
	// environment variables
	log.Printf("REGION: %s", os.Getenv("AWS_REGION"))
	log.Println("ALL ENV VARS:")
	vars := []string{"CYBR_TENANT_ID", "CYBR_SERVICE_ACCOUNT_ID", "CYBR_REGION"}
	for i, value := range vars {
		log.Printf("%s: %s", vars[i], os.Getenv(value))
	}
	// request context
	lc, _ := lambdacontext.FromContext(ctx)
	log.Printf("REQUEST ID: %s", lc.AwsRequestID)
	// global variable
	log.Printf("FUNCTION NAME: %s", lambdacontext.FunctionName)
	// context method
	deadline, _ := ctx.Deadline()
	log.Printf("DEADLINE: %s", deadline)
	// AWS SDK call
	usage, err := callLambda()
	if err != nil {
		ApiResponse = events.APIGatewayProxyResponse{Body: "Error generating Access Token", StatusCode: 404}
		return ApiResponse, err
	}
	ApiResponse = events.APIGatewayProxyResponse{Body: *usage, StatusCode: 200}
	return ApiResponse, nil
}

func main() {
	runtime.Start(handleRequest)
}
