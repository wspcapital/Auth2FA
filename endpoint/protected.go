package endpoint

import (
	"net/http"
	"github.com/gorilla/context"
	"encoding/json"
)

func ProtectedEndpoint(w http.ResponseWriter, req *http.Request) {
	decoded := context.Get(req, "decoded")
	json.NewEncoder(w).Encode(decoded)
}
