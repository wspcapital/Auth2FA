package endpoint

import (
	"net/http"
	"encoding/json"
	"github.com/Auth2FA/service"
	"github.com/jinzhu/gorm"
	"time"
	"github.com/gorilla/mux"
	"github.com/Auth2FA/model"
)

func VerifyOtpGetEndpoint(w http.ResponseWriter, req *http.Request) {
	bearerToken, err := service.GetBearerToken(req.Header.Get("authorization"))

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(err.Error())
		return
	}

	decodedToken, err := service.VerifyJwt(bearerToken, service.JWTSecret)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(err.Error())
		return
	}

	var user model.User

	err = service.DB.Connect.Table("users").
		Select("users.email, users.passw, users.salt, users.chat_id").
		Where("users.session_key =  ?", decodedToken["session_key"]).First(&user).Error

	if err != nil && gorm.IsRecordNotFoundError(err) == true {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode("JWT is incorrect")
		return
	} else if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(err.Error())
		return
	}

	if int64(decodedToken["expiresIn"].(float64)) < time.Now().Unix() {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode("Token is expired")
		return
	}

	vars := mux.Vars(req)
	if len(vars["otp"]) < 24 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode("Url Param 'otp' is missing")
		return
	}

	if decodedToken["authorized"] != false {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode("Invalid one-time password")
		return
	}

	if decodedToken["otp"] == vars["otp"] {
		tokenExp, err := service.GetTokenExpiredPeriod()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(err)
			return
		}

		decodedToken["authorized"] = true
		decodedToken["expiresIn"] = tokenExp
		delete(decodedToken, "otp")
	} else {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode("Invalid one-time password")
		return
	}

	jwToken, _ := service.SignJwt(decodedToken, service.JWTSecret)
	json.NewEncoder(w).Encode(service.JWTToken{Token: jwToken})
}
