package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestIAMLoginBodySignsForTheGlobalEndpoint(t *testing.T) {
	creds := aws.Credentials{AccessKeyID: "AKIAFAKEFAKEFAKEFAKE", SecretAccessKey: "FAKE-secret", SessionToken: "FAKE-session"}
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	body, err := iamLoginBody(context.Background(), creds, "apps-auth", at)
	if err != nil {
		t.Fatal(err)
	}
	dec := func(k string) string {
		raw, err := base64.StdEncoding.DecodeString(body[k])
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		return string(raw)
	}
	if body["role"] != "apps-auth" || body["iam_http_request_method"] != "POST" {
		t.Fatalf("body = %v", body)
	}
	if got := dec("iam_request_url"); got != "https://sts.amazonaws.com/" {
		t.Fatalf("url = %s", got)
	}
	if got := dec("iam_request_body"); got != stsBody {
		t.Fatalf("body = %s", got)
	}
	var headers http.Header
	if err := json.Unmarshal([]byte(dec("iam_request_headers")), &headers); err != nil {
		t.Fatal(err)
	}
	auth := headers.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIAFAKEFAKEFAKEFAKE/20261015/us-east-1/sts/aws4_request") {
		t.Fatalf("authorization = %s", auth)
	}
	if !strings.Contains(auth, "content-length") || !strings.Contains(auth, "content-type") || !strings.Contains(auth, "x-amz-security-token") {
		t.Fatalf("signed headers: %s", auth)
	}
	if headers.Get("X-Amz-Date") != "20261015T120000Z" || headers.Get("X-Amz-Security-Token") != "FAKE-session" {
		t.Fatalf("headers = %v", headers)
	}
	if headers.Get("Content-Length") != "43" {
		t.Fatalf("content-length = %q", headers.Get("Content-Length"))
	}
}
