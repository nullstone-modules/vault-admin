package admin

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

type recorded struct {
	method string
	path   string
	body   any
}

type fakeAPI struct {
	calls   []recorded
	roles   map[string][]string
	missing bool
}

func (f *fakeAPI) Call(_ context.Context, method, path string, body any) (int, []byte, error) {
	f.calls = append(f.calls, recorded{method: method, path: path, body: body})
	if method == "POST" && path == "/v1/sys/auth/aws" {
		return 400, []byte("path is already in use"), nil
	}
	if method == "LIST" && path == "/v1/auth/aws/role" {
		if f.roles == nil {
			return 404, []byte("none"), nil
		}
		keys := make([]string, 0, len(f.roles))
		for key := range f.roles {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		raw, err := json.Marshal(map[string]any{"data": map[string]any{"keys": keys}})
		if err != nil {
			return 500, nil, err
		}
		return 200, raw, nil
	}
	if method == "GET" && strings.HasPrefix(path, "/v1/auth/aws/role/") {
		name := strings.TrimPrefix(path, "/v1/auth/aws/role/")
		principals, ok := f.roles[name]
		if !ok {
			return 404, nil, nil
		}
		raw, err := json.Marshal(map[string]any{"data": map[string]any{"bound_iam_principal_arn": principals}})
		if err != nil {
			return 500, nil, err
		}
		return 200, raw, nil
	}
	if method == "DELETE" && f.missing {
		return 404, nil, nil
	}
	return 204, nil, nil
}

func writeCall(t *testing.T, api *fakeAPI) recorded {
	t.Helper()
	for _, call := range api.calls {
		if call.method == "POST" && strings.HasPrefix(call.path, "/v1/auth/aws/role/") {
			return call
		}
	}
	t.Fatal("role write was not called")
	return recorded{}
}

func TestEnsureRoleBindsOnlyTheGivenPrincipal(t *testing.T) {
	api := &fakeAPI{}
	err := EnsureRole(context.Background(), api, Event{
		Data: EventData{Name: "billing", BoundIAMPrincipalARN: "arn:aws:iam::1:role/app", Policies: []string{"app"}},
		Tf:   EventTf{Action: "create"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := writeCall(t, api).body.(map[string]any)
	arns := body["bound_iam_principal_arn"].([]string)
	policies := body["policies"].([]string)
	if len(arns) != 1 || arns[0] != "arn:aws:iam::1:role/app" || len(policies) != 1 || policies[0] != "app" {
		t.Fatalf("body = %#v", body)
	}
	if body["auth_type"] != "iam" {
		t.Fatalf("auth_type = %#v", body["auth_type"])
	}
}

func TestEnsureRoleRejectsAnotherName(t *testing.T) {
	api := &fakeAPI{}
	err := EnsureRole(context.Background(), api, Event{Data: EventData{Name: "../sys", BoundIAMPrincipalARN: "arn"}})
	if err == nil {
		t.Fatal("expected invalid role name to fail")
	}
	if len(api.calls) != 0 {
		t.Fatalf("invalid name must not call Vault, calls = %v", api.calls)
	}
}

func TestEnsureRoleRejectsPlatformAndTenantPolicies(t *testing.T) {
	for _, policy := range []string{"operator", "admin", "tenant-writer-other"} {
		api := &fakeAPI{}
		err := EnsureRole(context.Background(), api, Event{
			Data: EventData{Name: "billing", BoundIAMPrincipalARN: "arn:aws:iam::1:role/app", Policies: []string{policy}},
		})
		if err == nil {
			t.Fatalf("policy %s was accepted", policy)
		}
		if len(api.calls) != 0 {
			t.Fatalf("policy %s called Vault: %v", policy, api.calls)
		}
	}
}

func TestEnsureRoleRejectsRoleTakeover(t *testing.T) {
	api := &fakeAPI{roles: map[string][]string{"billing": {"arn:aws:iam::1:role/other"}}}
	err := EnsureRole(context.Background(), api, Event{
		Data: EventData{Name: "billing", BoundIAMPrincipalARN: "arn:aws:iam::1:role/app", Policies: []string{"app"}},
	})
	if err == nil {
		t.Fatal("expected a different principal to be rejected")
	}
	for _, call := range api.calls {
		if call.method == "POST" && strings.HasPrefix(call.path, "/v1/auth/aws/role/") {
			t.Fatal("takeover wrote the role")
		}
	}
}

func TestEnsureRoleRejectsPrincipalOnAnotherRole(t *testing.T) {
	api := &fakeAPI{roles: map[string][]string{"payments": {"arn:aws:iam::1:role/app"}}}
	err := EnsureRole(context.Background(), api, Event{
		Data: EventData{Name: "billing", BoundIAMPrincipalARN: "arn:aws:iam::1:role/app", Policies: []string{"app"}},
	})
	if err == nil {
		t.Fatal("expected an existing binding to be rejected")
	}
}

func TestEnsureRoleUpdateKeepsTheSamePrincipal(t *testing.T) {
	api := &fakeAPI{roles: map[string][]string{"billing": {"arn:aws:iam::1:role/app"}}}
	err := EnsureRole(context.Background(), api, Event{
		Data: EventData{Name: "billing", BoundIAMPrincipalARN: "arn:aws:iam::1:role/app", Policies: []string{"app"}},
		Tf:   EventTf{Action: "update"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if writeCall(t, api).path != "/v1/auth/aws/role/billing" {
		t.Fatal("update did not write billing")
	}
}

func TestEnsureRoleDeleteIgnoresMissing(t *testing.T) {
	api := &fakeAPI{missing: true}
	err := EnsureRole(context.Background(), api, Event{
		Data: EventData{Name: "billing"},
		Tf:   EventTf{Action: "delete"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(api.calls) != 1 || api.calls[0].method != "DELETE" || api.calls[0].path != "/v1/auth/aws/role/billing" {
		t.Fatalf("calls = %#v", api.calls)
	}
}

func TestEnsureRoleRejectsUnknownAction(t *testing.T) {
	api := &fakeAPI{}
	err := EnsureRole(context.Background(), api, Event{
		Data: EventData{Name: "billing", BoundIAMPrincipalARN: "arn:aws:iam::1:role/app"},
		Tf:   EventTf{Action: "noop"},
	})
	if err == nil {
		t.Fatal("expected unknown action to fail")
	}
	if len(api.calls) != 0 {
		t.Fatalf("calls = %#v", api.calls)
	}
}
