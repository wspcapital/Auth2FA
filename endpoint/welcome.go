package endpoint

import (
	"net/http"
	"encoding/json"
)

func WelcomeEndpoint(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode("Welcome!")
}
