package endpoint

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/context"
)

func ProtectedEndpoint(w http.ResponseWriter, req *http.Request) {
	decoded := context.Get(req, "decoded")
	json.NewEncoder(w).Encode(decoded)
}
