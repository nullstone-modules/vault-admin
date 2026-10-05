package main

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/nullstone-modules/vault-admin/admin"
)

var errEmptyToken = errors.New("vault token is empty")

func main() {
	lambda.Start(handle)
}

func handle(ctx context.Context, ev admin.Event) error {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}
	secretID := os.Getenv("VAULT_TOKEN_SECRET_ID")
	out, err := secretsmanager.NewFromConfig(cfg).GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &secretID,
	})
	if err != nil {
		return err
	}
	token := ""
	if out.SecretString != nil {
		token = strings.TrimSpace(*out.SecretString)
	}
	if token == "" {
		return errEmptyToken
	}
	return admin.EnsureRole(ctx, admin.HTTPAPI{
		Addr:          os.Getenv("VAULT_ADDR"),
		Token:         token,
		TLSServerName: os.Getenv("VAULT_TLS_SERVER_NAME"),
	}, ev)
}
