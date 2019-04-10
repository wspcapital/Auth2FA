package endpoint

import (
	"encoding/json"
	"net/http"

	"github.com/Auth2FA/model"
	"github.com/Auth2FA/service"
)

type signinUser struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func CreateTokenEndpoint(w http.ResponseWriter, req *http.Request) {
	var u signinUser
	if err := json.NewDecoder(req.Body).Decode(&u); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(err.Error())
		return
	}

	var user model.User
	if err := service.DB.Connect.Table("users").
		Select("users.id, users.email, users.passw, users.salt, users.chat_id, users.two_factor_email, users.two_factor_telegram").
		Where("users.email =  ?", u.Email).Find(&user).Error; err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(err.Error())
		return
	}

	if service.VerifyPassword(u.Password, user.Passw) == false {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode("Wrong password")
		return
	}

	otp := service.GetRandomString(24)
	sessionKey := service.GetRandomString(24)

	if err := service.DB.Connect.Model(&user).Update(map[string]interface{}{"session_key": sessionKey}).Error; err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(err)
		return
	}

	tokenExp, err := service.GetTokenExpiredOTPPeriod()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(err)
		return
	}

	authUser := make(map[string]interface{})
	authUser["expiresIn"] = tokenExp
	authUser["session_key"] = sessionKey
	authUser["otp"] = otp
	authUser["authorized"] = false

	tokenString, err := service.SignJwt(authUser, service.JWTSecret)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(err)
		return
	}

	var sentOtp bool
	if user.TwoFactorEmail {
		sentOtp, err = service.SendOtpByCurlEmail(u.Email, otp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(err.Error())
			return
		}
	} else if user.TwoFactorTelegram {
		sentOtp = service.SendOtpByTelegram(user.ChatID, otp)
	}
	if !sentOtp {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode("OTP is not sent")
		return
	}
	json.NewEncoder(w).Encode(service.JWTToken{Token: tokenString})
}
