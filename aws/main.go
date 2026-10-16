package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/nullstone-modules/vault-admin/admin"
)

func main() {
	lambda.Start(handle)
}

// handle logs in to Vault through auth/aws with the function's execution role, writes the role, and
// revokes its token. The cluster binds that role on auth/aws/role/apps-auth at bootstrap.
func handle(ctx context.Context, ev admin.Event) error {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return err
	}
	body, err := iamLoginBody(ctx, creds, admin.AppsAuthRole, time.Now())
	if err != nil {
		return err
	}
	api := admin.HTTPAPI{
		Addr:          os.Getenv("VAULT_ADDR"),
		TLSServerName: os.Getenv("VAULT_TLS_SERVER_NAME"),
	}
	token, err := admin.Login(ctx, api, "aws", admin.AppsAuthRole, body)
	if err != nil {
		return err
	}
	api.Token = token
	defer func() {
		if err := admin.RevokeSelf(ctx, api); err != nil {
			log.Printf("revoke token: %v", err)
		}
	}()
	return admin.EnsureRole(ctx, api, ev)
}
