package admin

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var roleName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

var deniedPolicies = map[string]struct{}{
	"admin":        {},
	"apps-auth":    {},
	"default":      {},
	"operator":     {},
	"provisioning": {},
	"root":         {},
}

// authMethod is one Vault auth mount an app can log in through. The mount path equals the method name.
type authMethod struct {
	principal *regexp.Regexp
	// boundField is the role field that lists bound principals.
	boundField string
	roleBody   func(principal string, policies []string) map[string]any
}

var authMethods = map[string]authMethod{
	"aws": {
		principal:  regexp.MustCompile(`^arn:aws[a-z-]*:iam::\d{12}:(role|user)/[\w+=,.@/-]+$`),
		boundField: "bound_iam_principal_arn",
		roleBody: func(principal string, policies []string) map[string]any {
			return map[string]any{
				"auth_type":               "iam",
				"bound_iam_principal_arn": []string{principal},
				"policies":                policies,
			}
		},
	},
	"gcp": {
		principal:  regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.gserviceaccount\.com$`),
		boundField: "bound_service_accounts",
		roleBody: func(principal string, policies []string) map[string]any {
			return map[string]any{
				"type":                   "iam",
				"bound_service_accounts": []string{principal},
				"policies":               policies,
			}
		},
	},
}

type Event struct {
	Data EventData `json:"data"`
	Tf   EventTf   `json:"tf"`
}

// EventData names one app principal: an IAM role or user ARN (aws) or a service account email (gcp).
type EventData struct {
	Name      string   `json:"name"`
	Method    string   `json:"method"`
	Principal string   `json:"principal"`
	Policies  []string `json:"policies"`
}

type EventTf struct {
	Action string `json:"action"`
}

type API interface {
	Call(ctx context.Context, method, path string, body any) (int, []byte, error)
}

type HTTPAPI struct {
	Addr  string
	Token string
	// TLSServerName overrides the name verified in the server certificate.
	TLSServerName string
	HTTP          *http.Client
}

func (a HTTPAPI) Call(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(a.Addr, "/")+path, r)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("X-Vault-Token", a.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := a.HTTP
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
		if a.TLSServerName != "" {
			client.Transport = &http.Transport{TLSClientConfig: &tls.Config{ServerName: a.TLSServerName, MinVersion: tls.VersionTLS12}}
		}
	}
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	return res.StatusCode, b, err
}

func EnsureRole(ctx context.Context, api API, ev Event) error {
	name := ev.Data.Name
	if !roleName.MatchString(name) {
		return fmt.Errorf("invalid vault role name")
	}
	method, ok := authMethods[ev.Data.Method]
	if !ok {
		return fmt.Errorf("unknown auth method")
	}
	action := ev.Tf.Action
	if action == "" {
		action = "create"
	}
	switch action {
	case "delete":
		return deleteRole(ctx, api, ev.Data.Method, name)
	case "create", "update":
		return writeRole(ctx, api, ev.Data.Method, method, name, ev.Data)
	default:
		return fmt.Errorf("invalid action")
	}
}

func deleteRole(ctx context.Context, api API, mount, name string) error {
	status, _, err := api.Call(ctx, http.MethodDelete, "/v1/auth/"+mount+"/role/"+name, nil)
	if err != nil {
		return err
	}
	if status >= 400 && status != http.StatusNotFound {
		return fmt.Errorf("delete role failed: %d", status)
	}
	return nil
}

func writeRole(ctx context.Context, api API, mount string, method authMethod, name string, data EventData) error {
	if !method.principal.MatchString(data.Principal) {
		return fmt.Errorf("invalid %s principal", mount)
	}
	policies := data.Policies
	if policies == nil {
		policies = []string{}
	}
	if err := validatePolicies(policies); err != nil {
		return err
	}
	if err := enableAuth(ctx, api, mount); err != nil {
		return err
	}
	if err := guardBinding(ctx, api, mount, method, name, data.Principal); err != nil {
		return err
	}
	status, _, err := api.Call(ctx, http.MethodPost, "/v1/auth/"+mount+"/role/"+name, method.roleBody(data.Principal, policies))
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("write role failed: %d", status)
	}
	return nil
}

func validatePolicies(policies []string) error {
	for _, policy := range policies {
		if !roleName.MatchString(policy) {
			return fmt.Errorf("invalid vault policy name")
		}
		if _, denied := deniedPolicies[policy]; denied || strings.HasPrefix(policy, "tenant-") {
			return fmt.Errorf("vault policy is not allowed")
		}
	}
	return nil
}

func enableAuth(ctx context.Context, api API, mount string) error {
	status, body, err := api.Call(ctx, http.MethodPost, "/v1/sys/auth/"+mount, map[string]string{"type": mount})
	if err != nil {
		return err
	}
	if status >= 400 && !bytes.Contains(body, []byte("already in use")) {
		return fmt.Errorf("enable %s auth failed: %d", mount, status)
	}
	return nil
}

// guardBinding keeps one principal per role and one role per principal on a mount.
func guardBinding(ctx context.Context, api API, mount string, method authMethod, name, principal string) error {
	status, body, err := api.Call(ctx, "LIST", "/v1/auth/"+mount+"/role", nil)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return nil
	}
	if status >= 400 {
		return fmt.Errorf("list roles failed: %d", status)
	}
	var listed struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		return fmt.Errorf("list roles failed")
	}
	for _, key := range listed.Data.Keys {
		if !roleName.MatchString(key) {
			return fmt.Errorf("invalid vault role name")
		}
		bound, found, err := readBoundPrincipals(ctx, api, mount, method, key)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		if key == name {
			if len(bound) != 1 || bound[0] != principal {
				return fmt.Errorf("vault role is bound to a different principal")
			}
			continue
		}
		for _, p := range bound {
			if p == principal {
				return fmt.Errorf("principal is already bound to vault role %s", key)
			}
		}
	}
	return nil
}

func readBoundPrincipals(ctx context.Context, api API, mount string, method authMethod, name string) ([]string, bool, error) {
	status, body, err := api.Call(ctx, http.MethodGet, "/v1/auth/"+mount+"/role/"+name, nil)
	if err != nil {
		return nil, false, err
	}
	if status == http.StatusNotFound {
		return nil, false, nil
	}
	if status >= 400 {
		return nil, false, fmt.Errorf("read role failed: %d", status)
	}
	var role struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &role); err != nil {
		return nil, false, fmt.Errorf("read role failed")
	}
	var bound []string
	if raw, ok := role.Data[method.boundField]; ok {
		if err := json.Unmarshal(raw, &bound); err != nil {
			return nil, false, fmt.Errorf("read role failed")
		}
	}
	return bound, true, nil
}
