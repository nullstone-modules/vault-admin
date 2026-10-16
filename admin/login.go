package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// ErrAuthNotEnabled reports a mount bootstrap has not created yet.
type ErrAuthNotEnabled struct{ Mount string }

func (e ErrAuthNotEnabled) Error() string {
	return "auth/" + e.Mount + " not enabled: run bootstrap on the cluster"
}

// vaultErrors returns the errors Vault put in a failure body, joined, or the raw body when it is not Vault's shape.
func vaultErrors(raw []byte) string {
	var res struct {
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal(raw, &res); err == nil && len(res.Errors) > 0 {
		return strings.Join(res.Errors, "; ")
	}
	return strings.TrimSpace(string(raw))
}

// statusError is a failed Vault call: the status, what Vault said, and what to do about it when the status alone says.
func statusError(what string, status int, raw []byte, hint string) error {
	msg := fmt.Sprintf("%s: %d", what, status)
	if said := vaultErrors(raw); said != "" {
		msg += ": " + said
	}
	if hint != "" {
		msg += " (" + hint + ")"
	}
	return fmt.Errorf("%s", msg)
}

// Login exchanges a login body on one auth mount for a client token. Vault answers 400 with the reason when the
// caller is not bound on the role; it answers 403 only when the path is not a login path at this address, which
// means the mount is missing here.
func Login(ctx context.Context, api API, mount, role string, body map[string]string) (string, error) {
	status, raw, err := api.Call(ctx, http.MethodPost, "/v1/auth/"+mount+"/login", body)
	if err != nil {
		return "", err
	}
	switch {
	case status == http.StatusNotFound:
		return "", ErrAuthNotEnabled{Mount: mount}
	case status == http.StatusForbidden:
		return "", statusError("vault login failed", status, raw, fmt.Sprintf("auth/%s is not a login path at VAULT_ADDR: is the mount enabled on this cluster?", mount))
	case status == http.StatusBadRequest:
		return "", statusError("vault login failed", status, raw, fmt.Sprintf("if the principal is not bound, run bootstrap or configure on the cluster to rewrite auth/%s/role/%s", mount, role))
	case status >= 400:
		return "", statusError("vault login failed", status, raw, "")
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
	status, raw, err := api.Call(ctx, http.MethodPost, "/v1/auth/token/revoke-self", nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return statusError("revoke token failed", status, raw, "")
	}
	return nil
}

// AppsAuthRole is the auth role the cluster writes for this function at bootstrap. Its token carries the
// apps-auth policy.
const AppsAuthRole = "apps-auth"
