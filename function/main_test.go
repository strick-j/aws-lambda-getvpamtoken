package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
)

// TestRandSequence calls randSequence with a value of 20
// and checks for a valid response
func TestRandSequence(t *testing.T) {
	want := regexp.MustCompile("^([a-zA-Z]{20})$")
	sequence := randSeq(20)
	if !want.MatchString(sequence) {
		t.Fatalf("randSeq(20) = %q, want match for %#q, nil", sequence, want)
	}
}

// TestCheckTenant_IsCorrectForValidInput calls checkTenant with
// valid inputs
func TestCheckTenant_IsCorrectForValidInput(t *testing.T) {
	var tests = []struct {
		name  string
		input string
		want  string
	}{
		{"ValidID1", "11ed307a252abc12345ab76ae4e1234a", "11ed307a252abc12345ab76ae4e1234a"},
		{"ValidID2", "12ed305a257abc15645ab76ae4e1234a", "12ed305a257abc15645ab76ae4e1234a"},
		{"ValidID3", "12ed305a257abc15645ab76ae4e1234A", "12ed305a257abc15645ab76ae4e1234a"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("CYBR_TENANT_ID", tt.input)
			got, err := checkTenant()
			if err != nil {
				t.Fatal(err)
			}
			if *got != tt.want {
				t.Errorf("got %s, want %s", *got, tt.want)
			}
		})
	}
}

// TestCheckTenant_ErrorsOnInvalidINput calls checkTenant with
// invalid inputs
func TestCheckTenant_ErrorsOnInvalidInput(t *testing.T) {
	var tests = []struct {
		name  string
		input string
	}{
		{"InvalidID1", "11ed307a252abc12345ab76a"},
		{"InvalidID2", "12ed305a257abc15645ab76ae4e1234a1224352"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("CYBR_TENANT_ID", tt.input)
			_, err := checkTenant()
			if err == nil {
				t.Error("want error for invalid input")
			}
		})
	}
}

// TestCheckServiceAccount_IsCorrectForValidInput calls checkTenant with
// valid inputs
func TestCheckServiceAccountt_IsCorrectForValidInput(t *testing.T) {
	var tests = []struct {
		name  string
		input string
		want  string
	}{
		{"ValidID1", "11ed307a252abc12345ab76ae4e1234a", "11ed307a252abc12345ab76ae4e1234a"},
		{"ValidID2", "12ed305a257abc15645ab76ae4e1234a", "12ed305a257abc15645ab76ae4e1234a"},
		{"ValidID3", "12ed305a257abc15645ab76ae4e1234A", "12ed305a257abc15645ab76ae4e1234a"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("CYBR_SERVICE_ACCOUNT_ID", tt.input)
			got, err := checkServiceAccount()
			if err != nil {
				t.Fatal(err)
			}
			if *got != tt.want {
				t.Errorf("got %s, want %s", *got, tt.want)
			}
		})
	}
}

// TestCheckServiceAccount_ErrorsOnInvalidINput calls checkTenant with
// invalid inputs
func TestCheckServiceAccount_ErrorsOnInvalidInput(t *testing.T) {
	var tests = []struct {
		name  string
		input string
	}{
		{"InvalidID1", "11ed307a252abc12345ab76a"},
		{"InvalidID2", "12ed305a257abc15645ab76ae4e1234a1224352"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("CYBR_SERVICE_ACCOUNT_ID", tt.input)
			_, err := checkServiceAccount()
			if err == nil {
				t.Error("want error for invalid input")
			}
		})
	}
}

// TestCheckRegion calls checkRegion with all valid regions and an invalid region
// and checks for the proper response
func TestCheckRegion(t *testing.T) {
	var tests = []struct {
		name  string
		input string
		want  string
	}{
		{"us", "us", "https://auth.alero.io/auth/realms/serviceaccounts"},
		{"eu", "EU", "https://auth.alero.eu/auth/realms/serviceaccounts"},
		{"canada", "CanAdA", "https://auth.ca.alero.io/auth/realms/serviceaccounts"},
		{"austraila", "austRAila", "https://auth.au.alero.io/auth/realms/serviceaccounts"},
		{"london", "LONDON", "https://auth.uk.alero.io/auth/realms/serviceaccounts"},
		{"india", "india", "https://auth.in.alero.io/auth/realms/serviceaccounts"},
		{"singapore", "singapore", "https://auth.sg.alero.io/auth/realms/serviceaccounts"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("CYBR_REGION", tt.input)
			ans, _ := checkRegion()
			if *ans != tt.want {
				t.Errorf("got %s, want %s", *ans, tt.want)
			}
		})
	}
}

// TestCheckPrivateKey_Valid Key verifies that the checkPrivateKey
// function validates a properly formatted key
func TestCheckPrivateKey_ValidKey(t *testing.T) {
	testKey := GenRSAKey(t)
	os.Setenv("CYBR_KEY", testKey)
	result, err := checkPrivateKey()
	if err != nil {
		t.Fatalf("error validating key, details: %v", err)
	}
	// Encode private key to PKCS#1 ASN.1 PEM.
	resultPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:    "RSA PRIVATE KEY",
			Headers: map[string]string{},
			Bytes:   x509.MarshalPKCS1PrivateKey(result),
		},
	)
	if testKey != string(resultPEM) {
		t.Errorf("returned key does match set key")
	}
}

// TestCheckPrivateKey_Valid Key verifies that the checkPrivateKey
// function validates a properly formatted key
func TestCheckPrivateKey_InvalidKey(t *testing.T) {
	testKey := GenRSAPKCS8Key(t)
	os.Setenv("CYBR_KEY", testKey)
	_, err := checkPrivateKey()
	if err == nil {
		t.Fatalf("want error when invalid key (pkcs8) is provided")
	}
}

// TestCallLambda_InvalidVariables calls callLambda with invalid or missing varibles
func TestCallLambda_InvalidVariables(t *testing.T) {
	testKey := GenRSAKey(t)
	var tests = []struct {
		name             string
		tenantId         string
		serviceAccountId string
		region           string
		key              string
	}{
		{"missing_tenant_id", "", "12ed305a257abc15645ab76ae4e1234a", "us", testKey},
		{"missing_service_account_id", "11ed307a252abc12345ab76ae4e1234a", "", "us", testKey},
		{"missing_region", "11ed307a252abc12345ab76ae4e1234a", "12ed305a257abc15645ab76ae4e1234a", "", testKey},
		{"missing_private_key", "11ed307a252abc12345ab76ae4e1234a", "12ed305a257abc15645ab76ae4e1234a", "us", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("CYBR_TENANT_ID", tt.tenantId)
			os.Setenv("CYBR_SERVICE_ACCOUNT_ID", tt.serviceAccountId)
			os.Setenv("CYBR_REGION", tt.region)
			os.Setenv("CYBR_KEY", tt.key)
			result, err := callLambda()
			if err == nil {
				t.Errorf("want error when variable is missing, %v", tt.name)
			}
			t.Log(result)
		})
	}
}

// TestCallLambda_ValidVariables calls callLambda with valid varibles
func TestCallLambda_ValidVariables(t *testing.T) {
	testKey := GenRSAKey(t)
	var tests = []struct {
		name             string
		tenantId         string
		serviceAccountId string
		region           string
		key              string
	}{
		{"test_1", "11ed307a252abc12345ab76ae4e1234a", "12ed305a257abc15645ab76ae4e1234a", "us", testKey},
		{"test_2", "11ed307a252abc12345ab76ae4e1234a", "12ed305a257abc15645ab76ae4e1234a", "Eu", testKey},
		{"test_3", "11ed307a252abc12345ab76ae4e1234a", "12ed305a257abc15645ab76ae4e1234a", "Canada", testKey},
		{"test_4", "11ed307a252abc12345ab76ae4e1234a", "12ed305a257abc15645ab76ae4e1234a", "us", testKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("CYBR_TENANT_ID", tt.tenantId)
			os.Setenv("CYBR_SERVICE_ACCOUNT_ID", tt.serviceAccountId)
			os.Setenv("CYBR_REGION", tt.region)
			os.Setenv("CYBR_KEY", tt.key)
			result, err := callLambda()
			if err != nil {
				t.Errorf("error calling lambda, details: %v", err)
			}
			t.Log(result)
		})
	}
}
func TestMain_ValidVariables(t *testing.T) {
	d := time.Now().Add(50 * time.Millisecond)
	os.Setenv("AWS_LAMBDA_FUNCTION_NAME", "aws-lambda-getvpamtoken-go")
	ctx, _ := context.WithDeadline(context.Background(), d)
	ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
		AwsRequestID:       "495b12a8-xmpl-4eca-8168-160484189f99",
		InvokedFunctionArn: "arn:aws:lambda:us-east-2:123456789012:function:aws-lambda-getvpamtoken-go",
	})
	var event events.APIGatewayProxyRequest
	// Set environment variables
	os.Setenv("CYBR_TENANT_ID", "11ed307a252abc12345ab76ae4e1234a")
	os.Setenv("CYBR_SERVICE_ACCOUNT_ID", "12ed305a257abc15645ab76ae4e1234a")
	os.Setenv("CYBR_REGION", "us")
	bitSize := 2048
	// Generate RSA key.
	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		t.Fatalf("error generating Private Key for test, details: %v", err)
	}
	// Encode private key to PKCS#1 ASN.1 PEM.
	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:    "RSA PRIVATE KEY",
			Headers: map[string]string{},
			Bytes:   x509.MarshalPKCS1PrivateKey(key),
		},
	)
	os.Setenv("CYBR_KEY", string(keyPEM))
	// inputEvent
	result, err := handleRequest(ctx, event)
	if err != nil {
		t.Log(err)
	}
	t.Log(result)
}

// Helper function to generate RSA Key for test purposes
func GenRSAKey(t *testing.T) string {
	bitSize := 2048
	// Generate RSA key.
	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		t.Fatalf("error generating Private Key for test, details: %v", err)
	}
	// Encode private key to PKCS#1 ASN.1 PEM.
	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:    "RSA PRIVATE KEY",
			Headers: map[string]string{},
			Bytes:   x509.MarshalPKCS1PrivateKey(key),
		},
	)
	return string(keyPEM)
}

// Helper function to generate PKCS8 RSA Key for test purposes
func GenRSAPKCS8Key(t *testing.T) string {
	bitSize := 2048
	// Generate RSA key.
	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		t.Fatalf("error generating Private Key for test, details: %v", err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("error marshaling private key")
	}
	// Encode private key to PKCS#1 ASN.1 PEM.
	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:    "PRIVATE KEY",
			Headers: map[string]string{},
			Bytes:   keyBytes,
		},
	)
	return string(keyPEM)
}
