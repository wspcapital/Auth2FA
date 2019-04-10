package endpoint

import (
	"net/http"
	"encoding/json"
	"github.com/Auth2FA/service"
	"github.com/jinzhu/gorm"
	"github.com/Auth2FA/model"
)

func RefreshJwtEndpoint(w http.ResponseWriter, req *http.Request) {
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
		Where("users.session_key =  ? ", decodedToken["session_key"]).First(&user).Error

	if err != nil && gorm.IsRecordNotFoundError(err) == true {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode("JWT is incorrect")
		return
	} else if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(err.Error())
		return
	}

	if decodedToken["authorized"] != true {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode("Token incorrect")
		return
	}

	sessionKey := service.GetRandomString(24)

	if err := service.DB.Connect.Model(&user).Update(map[string]interface{}{"session_key":sessionKey}).Error; err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(err)
		return
	}

	tokenExp, err := service.GetTokenExpiredPeriod()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(err)
		return
	}

	decodedToken["expiresIn"] = tokenExp
	decodedToken["session_key"] = sessionKey
	jwToken, _ := service.SignJwt(decodedToken, service.JWTSecret)
	json.NewEncoder(w).Encode(service.JWTToken{Token: jwToken})
}
