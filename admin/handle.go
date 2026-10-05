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

// Human admin roles are written by the cluster nodes, never by this function.
const reservedRolePrefix = "admin-"

var deniedPolicies = map[string]struct{}{
	"admin":        {},
	"aws-auth":     {},
	"default":      {},
	"operator":     {},
	"provisioning": {},
	"root":         {},
}

type Event struct {
	Data EventData `json:"data"`
	Tf   EventTf   `json:"tf"`
}

type EventData struct {
	Name                 string   `json:"name"`
	BoundIAMPrincipalARN string   `json:"bound_iam_principal_arn"`
	Policies             []string `json:"policies"`
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
	if strings.HasPrefix(name, reservedRolePrefix) {
		return fmt.Errorf("vault role name is reserved")
	}
	action := ev.Tf.Action
	if action == "" {
		action = "create"
	}
	switch action {
	case "delete":
		return deleteRole(ctx, api, name)
	case "create", "update":
		return writeRole(ctx, api, name, ev.Data)
	default:
		return fmt.Errorf("invalid action")
	}
}

func deleteRole(ctx context.Context, api API, name string) error {
	status, _, err := api.Call(ctx, http.MethodDelete, "/v1/auth/aws/role/"+name, nil)
	if err != nil {
		return err
	}
	if status >= 400 && status != http.StatusNotFound {
		return fmt.Errorf("delete role failed: %d", status)
	}
	return nil
}

func writeRole(ctx context.Context, api API, name string, data EventData) error {
	if data.BoundIAMPrincipalARN == "" {
		return fmt.Errorf("bound_iam_principal_arn is required")
	}
	policies := data.Policies
	if policies == nil {
		policies = []string{}
	}
	if err := validatePolicies(policies); err != nil {
		return err
	}
	if err := enableAWSAuth(ctx, api); err != nil {
		return err
	}
	if err := guardBinding(ctx, api, name, data.BoundIAMPrincipalARN); err != nil {
		return err
	}
	status, _, err := api.Call(ctx, http.MethodPost, "/v1/auth/aws/role/"+name, map[string]any{
		"auth_type":               "iam",
		"bound_iam_principal_arn": []string{data.BoundIAMPrincipalARN},
		"policies":                policies,
	})
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

func enableAWSAuth(ctx context.Context, api API) error {
	status, body, err := api.Call(ctx, http.MethodPost, "/v1/sys/auth/aws", map[string]string{"type": "aws"})
	if err != nil {
		return err
	}
	if status >= 400 && !bytes.Contains(body, []byte("already in use")) {
		return fmt.Errorf("enable aws auth failed: %d", status)
	}
	return nil
}

func guardBinding(ctx context.Context, api API, name, principal string) error {
	status, body, err := api.Call(ctx, "LIST", "/v1/auth/aws/role", nil)
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
		bound, found, err := readBoundPrincipals(ctx, api, key)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		if key == name {
			if len(bound) != 1 || bound[0] != principal {
				return fmt.Errorf("vault role is bound to a different iam principal")
			}
			continue
		}
		for _, arn := range bound {
			if arn == principal {
				return fmt.Errorf("iam principal is already bound to vault role %s", key)
			}
		}
	}
	return nil
}

func readBoundPrincipals(ctx context.Context, api API, name string) ([]string, bool, error) {
	status, body, err := api.Call(ctx, http.MethodGet, "/v1/auth/aws/role/"+name, nil)
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
		Data struct {
			Bound []string `json:"bound_iam_principal_arn"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &role); err != nil {
		return nil, false, fmt.Errorf("read role failed")
	}
	return role.Data.Bound, true, nil
}
