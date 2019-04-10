package endpoint

import (
	"net/http"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"encoding/json"
	"github.com/Auth2FA/service"
	"github.com/Auth2FA/model"
)

func SetEmailNoteEndpoint(w http.ResponseWriter, req *http.Request) {
	decoded := context.Get(req, "decoded")

	var setParam bool
	vars := mux.Vars(req)
	if vars["set-param"] == "1" {
		setParam = true
	} else if vars["set-param"] == "0" {
		setParam = false
	} else {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode("Set param is incorrect")
		return
	}

	mapJWT, ok := decoded.(map[string]interface{})
	if ok {
		var user model.User

		if err := service.DB.Connect.Table("users").
			Select("users.*").
			Where("users.session_key =  ?", mapJWT["session_key"]).First(&user).Error; err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(err.Error())
			return
		}

		if user.TwoFactorEmail != setParam {
			if err := service.DB.Connect.Model(&user).Update(map[string]interface{}{"two_factor_email":setParam}).Error; err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(err.Error())
				return
			}
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode("Email notification is set to " + vars["set-param"] + " for user " + user.Email)
	} else {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode("JWT is incorrect")
	}
}
