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

// fakeAPI serves one auth mount (default aws). roles maps role name to its bound principals.
type fakeAPI struct {
	mount   string
	calls   []recorded
	roles   map[string][]string
	missing bool
}

func (f *fakeAPI) mountName() string {
	if f.mount == "" {
		return "aws"
	}
	return f.mount
}

func (f *fakeAPI) rolePath() string {
	return "/v1/auth/" + f.mountName() + "/role"
}

func (f *fakeAPI) Call(_ context.Context, method, path string, body any) (int, []byte, error) {
	f.calls = append(f.calls, recorded{method: method, path: path, body: body})
	if method == "POST" && strings.HasPrefix(path, "/v1/sys/auth/") {
		return 400, []byte("path is already in use"), nil
	}
	if method == "LIST" && path == f.rolePath() {
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
	if method == "GET" && strings.HasPrefix(path, f.rolePath()+"/") {
		name := strings.TrimPrefix(path, f.rolePath()+"/")
		principals, ok := f.roles[name]
		if !ok {
			return 404, nil, nil
		}
		field := authMethods[f.mountName()].boundField
		raw, err := json.Marshal(map[string]any{"data": map[string]any{field: principals}})
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
		if call.method == "POST" && strings.HasPrefix(call.path, api.rolePath()+"/") {
			return call
		}
	}
	t.Fatal("role write was not called")
	return recorded{}
}

const appARN = "arn:aws:iam::123456789012:role/app"

func awsEvent(name string, policies ...string) Event {
	return Event{Data: EventData{Name: name, Method: "aws", Principal: appARN, Policies: policies}}
}

func TestEnsureRoleBindsOnlyTheGivenPrincipal(t *testing.T) {
	api := &fakeAPI{}
	ev := awsEvent("billing", "apps-reader")
	ev.Tf.Action = "create"
	if err := EnsureRole(context.Background(), api, ev); err != nil {
		t.Fatal(err)
	}
	body := writeCall(t, api).body.(map[string]any)
	arns := body["bound_iam_principal_arn"].([]string)
	policies := body["policies"].([]string)
	if len(arns) != 1 || arns[0] != appARN || len(policies) != 1 || policies[0] != "apps-reader" {
		t.Fatalf("body = %#v", body)
	}
	if body["auth_type"] != "iam" {
		t.Fatalf("auth_type = %#v", body["auth_type"])
	}
}

func TestEnsureRoleWritesGCPServiceAccounts(t *testing.T) {
	api := &fakeAPI{mount: "gcp", roles: map[string][]string{"payments": {"other@proj.iam.gserviceaccount.com"}}}
	err := EnsureRole(context.Background(), api, Event{
		Data: EventData{Name: "billing", Method: "gcp", Principal: "app@proj.iam.gserviceaccount.com", Policies: []string{"apps-writer"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	call := writeCall(t, api)
	if call.path != "/v1/auth/gcp/role/billing" {
		t.Fatalf("path = %s", call.path)
	}
	body := call.body.(map[string]any)
	sas := body["bound_service_accounts"].([]string)
	if body["type"] != "iam" || len(sas) != 1 || sas[0] != "app@proj.iam.gserviceaccount.com" {
		t.Fatalf("body = %#v", body)
	}
	if api.calls[0].path != "/v1/sys/auth/gcp" {
		t.Fatalf("first call = %#v", api.calls[0])
	}
}

func TestEnsureRoleRejectsUnknownMethodAndBadPrincipals(t *testing.T) {
	tests := []EventData{
		{Name: "billing", Method: "", Principal: appARN},
		{Name: "billing", Method: "azure", Principal: "x"},
		{Name: "billing", Method: "aws", Principal: "app@proj.iam.gserviceaccount.com"},
		{Name: "billing", Method: "aws", Principal: "arn:aws:iam::123456789012:group/admins"},
		{Name: "billing", Method: "aws", Principal: "arn:aws:iam::123456789012:role/*"},
		{Name: "billing", Method: "gcp", Principal: appARN},
		{Name: "billing", Method: "gcp", Principal: "someone@example.com"},
	}
	for _, data := range tests {
		api := &fakeAPI{mount: data.Method}
		if err := EnsureRole(context.Background(), api, Event{Data: data}); err == nil {
			t.Fatalf("%+v was accepted", data)
		}
		for _, call := range api.calls {
			if call.method == "POST" && strings.Contains(call.path, "/role/") {
				t.Fatalf("%+v wrote a role", data)
			}
		}
	}
}

func TestEnsureRoleRejectsAnotherName(t *testing.T) {
	api := &fakeAPI{}
	err := EnsureRole(context.Background(), api, Event{Data: EventData{Name: "../sys", Method: "aws", Principal: appARN}})
	if err == nil {
		t.Fatal("expected invalid role name to fail")
	}
	if len(api.calls) != 0 {
		t.Fatalf("invalid name must not call Vault, calls = %v", api.calls)
	}
}

func TestEnsureRoleRejectsPlatformAndTenantPolicies(t *testing.T) {
	for _, policy := range []string{"operator", "admin", "apps-auth", "provisioning", "tenant-writer-other", "app", "apps-admin"} {
		api := &fakeAPI{}
		if err := EnsureRole(context.Background(), api, awsEvent("billing", policy)); err == nil {
			t.Fatalf("policy %s was accepted", policy)
		}
		if len(api.calls) != 0 {
			t.Fatalf("policy %s called Vault: %v", policy, api.calls)
		}
	}
}

func TestEnsureRoleRejectsRoleTakeover(t *testing.T) {
	api := &fakeAPI{roles: map[string][]string{"billing": {"arn:aws:iam::123456789012:role/other"}}}
	if err := EnsureRole(context.Background(), api, awsEvent("billing", "apps-reader")); err == nil {
		t.Fatal("expected a different principal to be rejected")
	}
	for _, call := range api.calls {
		if call.method == "POST" && strings.HasPrefix(call.path, "/v1/auth/aws/role/") {
			t.Fatal("takeover wrote the role")
		}
	}
}

func TestEnsureRoleRejectsPrincipalOnAnotherRole(t *testing.T) {
	api := &fakeAPI{roles: map[string][]string{"payments": {appARN}}}
	if err := EnsureRole(context.Background(), api, awsEvent("billing", "apps-reader")); err == nil {
		t.Fatal("expected an existing binding to be rejected")
	}
}

func TestEnsureRoleUpdateKeepsTheSamePrincipal(t *testing.T) {
	api := &fakeAPI{roles: map[string][]string{"billing": {appARN}}}
	ev := awsEvent("billing", "apps-reader")
	ev.Tf.Action = "update"
	if err := EnsureRole(context.Background(), api, ev); err != nil {
		t.Fatal(err)
	}
	if writeCall(t, api).path != "/v1/auth/aws/role/billing" {
		t.Fatal("update did not write billing")
	}
}

func TestEnsureRoleDeleteIgnoresMissing(t *testing.T) {
	for _, mount := range []string{"aws", "gcp"} {
		api := &fakeAPI{mount: mount, missing: true}
		err := EnsureRole(context.Background(), api, Event{
			Data: EventData{Name: "billing", Method: mount},
			Tf:   EventTf{Action: "delete"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(api.calls) != 1 || api.calls[0].method != "DELETE" || api.calls[0].path != "/v1/auth/"+mount+"/role/billing" {
			t.Fatalf("calls = %#v", api.calls)
		}
	}
}

func TestEnsureRoleRejectsUnknownAction(t *testing.T) {
	api := &fakeAPI{}
	ev := awsEvent("billing")
	ev.Tf.Action = "noop"
	if err := EnsureRole(context.Background(), api, ev); err == nil {
		t.Fatal("expected unknown action to fail")
	}
	if len(api.calls) != 0 {
		t.Fatalf("calls = %#v", api.calls)
	}
}
