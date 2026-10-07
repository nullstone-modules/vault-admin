package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
)

// envName is a Nullstone env name as a path segment: the tenant ID character class, never ".".
var envName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{1,30}[a-z0-9])$`)

// entityName is the identity entity for one app role on one auth mount.
func entityName(mount, role string) string {
	return mount + "/" + role
}

// ensureEntity gives the app role an entity whose metadata carries env, aliased by the role's role_id so every
// login through that role lands on it (aws and gcp alias by role_id by default). The cluster's broker policies
// template that env. Re-runs are no-ops; an entity Vault auto-created for an earlier login is unlinked.
func ensureEntity(ctx context.Context, api API, mount, role, env string) error {
	roleID, err := readRoleID(ctx, api, mount, role)
	if err != nil {
		return err
	}
	accessor, err := authAccessor(ctx, api, mount)
	if err != nil {
		return err
	}
	name := entityName(mount, role)
	status, _, err := api.Call(ctx, http.MethodPost, "/v1/identity/entity/name/"+name, map[string]any{
		"metadata": map[string]string{"env": env, "method": mount, "role": role},
	})
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("write entity failed: %d", status)
	}
	entityID, err := readEntityID(ctx, api, name)
	if err != nil {
		return err
	}

	status, body, err := api.Call(ctx, http.MethodPost, "/v1/identity/lookup/entity", map[string]any{
		"alias_name": roleID, "alias_mount_accessor": accessor,
	})
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("lookup entity failed: %d", status)
	}
	if status != http.StatusNoContent && len(body) > 0 {
		var found struct {
			Data struct {
				ID      string `json:"id"`
				Aliases []struct {
					ID            string `json:"id"`
					Name          string `json:"name"`
					MountAccessor string `json:"mount_accessor"`
				} `json:"aliases"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &found); err != nil {
			return fmt.Errorf("lookup entity failed")
		}
		if found.Data.ID == entityID {
			return nil
		}
		for _, a := range found.Data.Aliases {
			if a.Name == roleID && a.MountAccessor == accessor {
				status, _, err := api.Call(ctx, http.MethodDelete, "/v1/identity/entity-alias/id/"+a.ID, nil)
				if err != nil {
					return err
				}
				if status >= 400 && status != http.StatusNotFound {
					return fmt.Errorf("unlink stale alias failed: %d", status)
				}
			}
		}
	}
	status, _, err = api.Call(ctx, http.MethodPost, "/v1/identity/entity-alias", map[string]any{
		"name": roleID, "canonical_id": entityID, "mount_accessor": accessor,
	})
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("write entity alias failed: %d", status)
	}
	return nil
}

func deleteEntity(ctx context.Context, api API, mount, role string) error {
	status, _, err := api.Call(ctx, http.MethodDelete, "/v1/identity/entity/name/"+entityName(mount, role), nil)
	if err != nil {
		return err
	}
	if status >= 400 && status != http.StatusNotFound {
		return fmt.Errorf("delete entity failed: %d", status)
	}
	return nil
}

func readRoleID(ctx context.Context, api API, mount, role string) (string, error) {
	status, body, err := api.Call(ctx, http.MethodGet, "/v1/auth/"+mount+"/role/"+role, nil)
	if err != nil {
		return "", err
	}
	if status >= 400 {
		return "", fmt.Errorf("read role failed: %d", status)
	}
	var r struct {
		Data struct {
			RoleID string `json:"role_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Data.RoleID == "" {
		return "", fmt.Errorf("role has no role_id")
	}
	return r.Data.RoleID, nil
}

func authAccessor(ctx context.Context, api API, mount string) (string, error) {
	status, body, err := api.Call(ctx, http.MethodGet, "/v1/sys/auth", nil)
	if err != nil {
		return "", err
	}
	if status >= 400 {
		return "", fmt.Errorf("list auth mounts failed: %d", status)
	}
	var mounts struct {
		Data map[string]struct {
			Accessor string `json:"accessor"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &mounts); err != nil {
		return "", fmt.Errorf("list auth mounts failed")
	}
	m, ok := mounts.Data[mount+"/"]
	if !ok {
		// Older Vault returns the mounts at the top level.
		var top map[string]json.RawMessage
		if err := json.Unmarshal(body, &top); err == nil {
			if raw, ok := top[mount+"/"]; ok {
				var entry struct {
					Accessor string `json:"accessor"`
				}
				if json.Unmarshal(raw, &entry) == nil && entry.Accessor != "" {
					return entry.Accessor, nil
				}
			}
		}
		return "", fmt.Errorf("auth mount %s not found", mount)
	}
	if m.Accessor == "" {
		return "", fmt.Errorf("auth mount %s has no accessor", mount)
	}
	return m.Accessor, nil
}

func readEntityID(ctx context.Context, api API, name string) (string, error) {
	status, body, err := api.Call(ctx, http.MethodGet, "/v1/identity/entity/name/"+name, nil)
	if err != nil {
		return "", err
	}
	if status >= 400 {
		return "", fmt.Errorf("read entity failed: %d", status)
	}
	var e struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &e); err != nil || e.Data.ID == "" {
		return "", fmt.Errorf("entity has no id")
	}
	return e.Data.ID, nil
}
