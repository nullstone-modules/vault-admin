package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// ErrAuthNotEnabled reports a mount bootstrap has not created yet.
type ErrAuthNotEnabled struct{ Mount string }

func (e ErrAuthNotEnabled) Error() string {
	return "auth/" + e.Mount + " not enabled: run bootstrap on the cluster"
}

// Login exchanges a login body on one auth mount for a client token. A 403 names the fix: the function's
// principal is not bound on the role the cluster writes at bootstrap.
func Login(ctx context.Context, api API, mount, role string, body map[string]string) (string, error) {
	status, raw, err := api.Call(ctx, http.MethodPost, "/v1/auth/"+mount+"/login", body)
	if err != nil {
		return "", err
	}
	switch {
	case status == http.StatusNotFound:
		return "", ErrAuthNotEnabled{Mount: mount}
	case status == http.StatusForbidden:
		return "", fmt.Errorf("vault login failed: 403: the function role is not bound on auth/%s/role/%s; run bootstrap or configure on the cluster", mount, role)
	case status >= 400:
		return "", fmt.Errorf("vault login failed: %d", status)
	}
	var res struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(raw, &res); err != nil || res.Auth.ClientToken == "" {
		return "", fmt.Errorf("vault login returned no token")
	}
	return res.Auth.ClientToken, nil
}

// RevokeSelf revokes the token api carries. The token expires on its own; this just shortens the window.
func RevokeSelf(ctx context.Context, api API) error {
	status, _, err := api.Call(ctx, http.MethodPost, "/v1/auth/token/revoke-self", nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("revoke token failed: %d", status)
	}
	return nil
}

// AppsAuthRole is the auth role the cluster writes for this function at bootstrap. Its token carries the
// apps-auth policy.
const AppsAuthRole = "apps-auth"
