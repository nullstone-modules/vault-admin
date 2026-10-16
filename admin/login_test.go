package admin

import (
	"context"
	"strings"
	"testing"
)

type loginAPI struct {
	status int
	body   string
	calls  []recorded
}

func (f *loginAPI) Call(_ context.Context, method, path string, body any) (int, []byte, error) {
	f.calls = append(f.calls, recorded{method: method, path: path, body: body})
	return f.status, []byte(f.body), nil
}

func TestLoginReturnsTheClientToken(t *testing.T) {
	api := &loginAPI{status: 200, body: `{"auth":{"client_token":"hvs.FAKE-login"}}`}
	tok, err := Login(context.Background(), api, "aws", "apps-auth", map[string]string{"role": "apps-auth"})
	if err != nil || tok != "hvs.FAKE-login" {
		t.Fatalf("tok = %q err = %v", tok, err)
	}
	if c := api.calls[0]; c.method != "POST" || c.path != "/v1/auth/aws/login" {
		t.Fatalf("call = %+v", c)
	}
}

func TestLoginNamesTheCause(t *testing.T) {
	cases := map[int]string{
		403: "not bound on auth/aws/role/apps-auth",
		404: "auth/aws not enabled",
		500: "vault login failed: 500",
	}
	for status, want := range cases {
		api := &loginAPI{status: status, body: `{"errors":["permission denied"]}`}
		_, err := Login(context.Background(), api, "aws", "apps-auth", nil)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%d: err = %v, want %q", status, err, want)
		}
	}
	api := &loginAPI{status: 200, body: `{"auth":null}`}
	if _, err := Login(context.Background(), api, "aws", "apps-auth", nil); err == nil {
		t.Fatal("a login without a token was accepted")
	}
}

func TestRevokeSelf(t *testing.T) {
	api := &loginAPI{status: 204}
	if err := RevokeSelf(context.Background(), api); err != nil {
		t.Fatal(err)
	}
	if c := api.calls[0]; c.path != "/v1/auth/token/revoke-self" {
		t.Fatalf("call = %+v", c)
	}
	if err := RevokeSelf(context.Background(), &loginAPI{status: 403}); err == nil {
		t.Fatal("403 was ignored")
	}
}
