package admin

import (
	"context"
	"strings"
	"testing"
)

func envEvent(name, env string) Event {
	ev := awsEvent(name, "apps-reader")
	ev.Data.Env = env
	return ev
}

func TestEnsureRoleWithEnvWritesEntityAndAlias(t *testing.T) {
	api := &fakeAPI{roles: map[string][]string{}}
	api.roles["billing"] = []string{appARN}
	if err := EnsureRole(context.Background(), api, envEvent("billing", "pr-12")); err != nil {
		t.Fatal(err)
	}
	if api.entities["aws/billing"] == "" {
		t.Fatalf("entity not written: %v", api.entities)
	}
	if got := api.aliases["rid-billing@"+fakeAccessor]; got != "ent-aws/billing" {
		t.Fatalf("alias = %q, aliases = %v", got, api.aliases)
	}
	var wrote bool
	for _, c := range api.identityCalls() {
		if c.method == "POST" && c.path == "/v1/identity/entity/name/aws/billing" {
			meta := c.body.(map[string]any)["metadata"].(map[string]string)
			if meta["env"] != "pr-12" || meta["method"] != "aws" || meta["role"] != "billing" {
				t.Fatalf("metadata = %v", meta)
			}
			if _, ok := c.body.(map[string]any)["policies"]; ok {
				t.Fatal("entity write must not carry policies")
			}
			wrote = true
		}
	}
	if !wrote {
		t.Fatalf("entity write missing: %v", api.identityCalls())
	}
	// The role is written before the entity, so a refused binding never leaves an entity behind.
	roleAt, entityAt := -1, -1
	for i, c := range api.calls {
		if c.method == "POST" && c.path == "/v1/auth/aws/role/billing" {
			roleAt = i
		}
		if c.method == "POST" && c.path == "/v1/identity/entity/name/aws/billing" {
			entityAt = i
		}
	}
	if roleAt < 0 || entityAt < roleAt {
		t.Fatalf("role at %d, entity at %d", roleAt, entityAt)
	}
}

func TestEnsureRoleWithEnvIsIdempotent(t *testing.T) {
	api := &fakeAPI{roles: map[string][]string{"billing": {appARN}}}
	for i := 0; i < 2; i++ {
		if err := EnsureRole(context.Background(), api, envEvent("billing", "pr-12")); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	if len(api.aliases) != 1 || len(api.entities) != 1 {
		t.Fatalf("entities = %v aliases = %v", api.entities, api.aliases)
	}
}

func TestEnsureRoleWithEnvRelinksAutoCreatedEntity(t *testing.T) {
	// A login before the function ran gave the role an entity without metadata.
	api := &fakeAPI{
		roles:    map[string][]string{"billing": {appARN}},
		entities: map[string]string{"entity_abc": "ent-auto"},
		aliases:  map[string]string{"rid-billing@" + fakeAccessor: "ent-auto"},
	}
	if err := EnsureRole(context.Background(), api, envEvent("billing", "pr-12")); err != nil {
		t.Fatal(err)
	}
	if got := api.aliases["rid-billing@"+fakeAccessor]; got != "ent-aws/billing" {
		t.Fatalf("alias still points at %q", got)
	}
	var unlinked bool
	for _, c := range api.identityCalls() {
		if c.method == "DELETE" && strings.HasPrefix(c.path, "/v1/identity/entity-alias/id/") {
			unlinked = true
		}
	}
	if !unlinked {
		t.Fatal("stale alias was not unlinked")
	}
}

func TestEnsureRoleWithoutEnvTouchesNoIdentity(t *testing.T) {
	api := &fakeAPI{roles: map[string][]string{}}
	for _, action := range []string{"create", "update", "delete"} {
		ev := awsEvent("billing", "apps-reader")
		ev.Tf.Action = action
		if err := EnsureRole(context.Background(), api, ev); err != nil {
			t.Fatal(err)
		}
	}
	if calls := api.identityCalls(); len(calls) != 0 {
		t.Fatalf("identity was called without env: %v", calls)
	}
	for _, c := range api.calls {
		if c.path == "/v1/sys/auth" {
			t.Fatal("sys/auth was read without env")
		}
	}
}

func TestEnsureRoleRejectsInvalidEnv(t *testing.T) {
	for _, env := range []string{"a.b", "a/b", "PR", "x", "pr-*", "-x", "x-", "a b"} {
		api := &fakeAPI{}
		if err := EnsureRole(context.Background(), api, envEvent("billing", env)); err == nil {
			t.Fatalf("env %q was accepted", env)
		}
		if len(api.calls) != 0 {
			t.Fatalf("env %q called Vault: %v", env, api.calls)
		}
	}
}

func TestEnsureRoleDeleteWithEnvDeletesEntityFirst(t *testing.T) {
	api := &fakeAPI{entities: map[string]string{"gcp/billing": "ent-gcp/billing"}, mount: "gcp"}
	ev := Event{Data: EventData{Name: "billing", Method: "gcp", Env: "pr-12"}, Tf: EventTf{Action: "delete"}}
	if err := EnsureRole(context.Background(), api, ev); err != nil {
		t.Fatal(err)
	}
	if len(api.calls) != 2 || api.calls[0].path != "/v1/identity/entity/name/gcp/billing" || api.calls[0].method != "DELETE" ||
		api.calls[1].path != "/v1/auth/gcp/role/billing" || api.calls[1].method != "DELETE" {
		t.Fatalf("calls = %#v", api.calls)
	}
	if _, ok := api.entities["gcp/billing"]; ok {
		t.Fatal("entity survived delete")
	}
	// A missing entity is fine.
	api = &fakeAPI{mount: "gcp", missing: true}
	if err := EnsureRole(context.Background(), api, ev); err != nil {
		t.Fatal(err)
	}
}
