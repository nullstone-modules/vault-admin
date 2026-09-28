package vault_admin

import (
	"encoding/json"
	"net/http"
	"os"

	_ "github.com/GoogleCloudPlatform/functions-framework-go/funcframework"
	"github.com/GoogleCloudPlatform/functions-framework-go/functions"
	"github.com/nullstone-modules/vault-admin/admin"
)

func init() {
	functions.HTTP("vault-admin", func(w http.ResponseWriter, r *http.Request) {
		var ev admin.Event
		if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
			http.Error(w, "invalid event", http.StatusBadRequest)
			return
		}
		token := os.Getenv("VAULT_TOKEN")
		if token == "" {
			http.Error(w, "vault token is empty", http.StatusBadGateway)
			return
		}
		err := admin.EnsureRole(r.Context(), admin.HTTPAPI{
			Addr:  os.Getenv("VAULT_ADDR"),
			Token: token,
		}, ev)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
