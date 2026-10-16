package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const stsBody = "Action=GetCallerIdentity&Version=2011-06-15"

// Vault replays the request to the global STS endpoint unless its aws mount is configured otherwise, and the
// global endpoint verifies signatures made for us-east-1. The signed URL and region must match that.
const (
	stsURL    = "https://sts.amazonaws.com/"
	stsRegion = "us-east-1"
)

// iamLoginBody signs an sts:GetCallerIdentity request with creds and packs it the way auth/aws/login expects.
// Vault replays the request to STS; the caller's identity must match the role's bound principal.
func iamLoginBody(ctx context.Context, creds aws.Credentials, role string, now time.Time) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, stsURL, strings.NewReader(stsBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Content-Length", strconv.Itoa(len(stsBody)))
	sum := sha256.Sum256([]byte(stsBody))
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, hex.EncodeToString(sum[:]), "sts", stsRegion, now); err != nil {
		return nil, err
	}
	headers, err := json.Marshal(req.Header)
	if err != nil {
		return nil, err
	}
	b64 := base64.StdEncoding.EncodeToString
	return map[string]string{
		"role":                    role,
		"iam_http_request_method": http.MethodPost,
		"iam_request_url":         b64([]byte(stsURL)),
		"iam_request_body":        b64([]byte(stsBody)),
		"iam_request_headers":     b64(headers),
	}, nil
}
