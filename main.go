package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/Auth2FA/model"
	"github.com/Auth2FA/service"
	"os"
	"time"

	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/joho/godotenv"
	"regexp"
	"strconv"
)

var jwtSecret string

type JWTToken struct {
	Token string `json:"token"`
}

type signinUser struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type newUser struct {
	FirstName    string `json:"firstname"`
	LastName     string `json:"lastname"`
	Email        string `json:"email"`
	Phone        string `json:"phone"`
	Password     string `json:"password"`
	ConfPassword string `json:"confpassword"`
	ChatID       int64  `json:"chatid"`
}

func ValidateMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		bearerToken, err := service.GetBearerToken(req.Header.Get("authorization"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(err.Error())
			return
		}

		decodedToken, err := service.VerifyJwt(bearerToken, jwtSecret)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(err.Error())
			return
		}

		var user model.User
		err = service.DB.Connect.Table("users").
			Select("users.email, users.passw, users.salt, users.chat_id").
			Where("users.session_key =  ?", decodedToken["session_key"]).First(&user).Error

		if gorm.IsRecordNotFoundError(err) {
			w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode("Access is incorrect")
			return
		} else if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(err.Error())
			return
		}

		if _, ok := decodedToken["expiresIn"].(float64); !ok {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode("Token is expired")
			return
		}

		if int64(decodedToken["expiresIn"].(float64)) < time.Now().Unix() {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode("Token is expired")
			return
		}

		if decodedToken["authorized"] == true {
			context.Set(req, "decoded", decodedToken)
			next(w, req)
		} else {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode("2FA is required")
		}
	})
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

	if err := service.DB.Connect.Model(&user).Update(map[string]interface{}{"session_key":sessionKey}).Error; err != nil {
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

	tokenString, err := service.SignJwt(authUser, jwtSecret)
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
	json.NewEncoder(w).Encode(JWTToken{Token: tokenString})
}

func ProtectedEndpoint(w http.ResponseWriter, req *http.Request) {
	decoded := context.Get(req, "decoded")
	json.NewEncoder(w).Encode(decoded)
}

func VerifyOtpGetEndpoint(w http.ResponseWriter, req *http.Request) {
	bearerToken, err := service.GetBearerToken(req.Header.Get("authorization"))

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(err.Error())
		return
	}

	decodedToken, err := service.VerifyJwt(bearerToken, jwtSecret)
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

	jwToken, _ := service.SignJwt(decodedToken, jwtSecret)
	json.NewEncoder(w).Encode(JWTToken{Token: jwToken})
}

func RefreshJwtEndpoint(w http.ResponseWriter, req *http.Request) {
	bearerToken, err := service.GetBearerToken(req.Header.Get("authorization"))

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(err.Error())
		return
	}

	decodedToken, err := service.VerifyJwt(bearerToken, jwtSecret)
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
	jwToken, _ := service.SignJwt(decodedToken, jwtSecret)
	json.NewEncoder(w).Encode(JWTToken{Token: jwToken})
}

func SignUpEndpoint(w http.ResponseWriter, req *http.Request) {
	var u newUser
	_ = json.NewDecoder(req.Body).Decode(&u)

	if !service.ValidateEmail(u.Email) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode("Incorrect Email address")
		return
	}

	var user model.User

	re, err := regexp.Compile(`\D`)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(err.Error())
		return
	}
	userPhone, err := strconv.ParseInt(re.ReplaceAllString(u.Phone, ""), 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(err.Error())
		return
	}

	err = service.DB.Connect.Table("users").
		Select("users.email, users.phone").
		Where("users.email =  ? or users.phone =  ?", u.Email, userPhone).First(&user).Error

	if gorm.IsRecordNotFoundError(err) == true {
		salt := service.GetRandomString(15)
		encodedPwd := salt + "$" + service.EncodePassword(u.Password, salt)

		User := model.User{
			FirstName:      u.FirstName,
			LastName:       u.LastName,
			Alias:          u.FirstName + "_" + u.LastName,
			Passw:          encodedPwd,
			Active:         true,
			Email:          u.Email,
			Phone:			userPhone,
			Salt:           salt,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
			ChatID:         u.ChatID,
			TwoFactorEmail: true,
		}

		if err := service.DB.Connect.Create(&User).Error; err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(err.Error())
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(User.ID)
		return
	} else if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(err.Error())
		return
	}
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte("Email " + user.Email + " OR " + strconv.FormatInt(user.Phone, 10) + " is used"))
}

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

func SetTelegramNoteEndpoint(w http.ResponseWriter, req *http.Request) {
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
		if err :=  service.DB.Connect.Table("users").
			Select("users.*").
			Where("users.session_key =  ?", mapJWT["session_key"]).First(&user).Error; err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(err.Error())
			return
		}

		if user.ChatID == 0 {
			if err := service.DB.Connect.Model(&user).Update(map[string]interface{}{"telegram_key_token":service.GetRandomString(24)}).Error; err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(err.Error())
				return
			}

			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode("To set telegram notification need verification by token " + user.TelegramKeyToken + " on bot t.me/TheCopierBot")
			return
		}

		if user.TwoFactorTelegram != setParam {
			user.TwoFactorTelegram = setParam

			if err := service.DB.Connect.Save(&user).Error; err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(err.Error())
				return
			}
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode("Telegram notification is set to " + vars["set-param"] + " for user " + user.Email)

	} else {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode("JWT is incorrect")
	}
}

var telegramBot service.TelegramBot

func main() {
	err := godotenv.Load()

	err = service.DB.Init()

	if err != nil {
		panic(err)
	}
	defer service.DB.Connect.Close()

	telegramBot.Init()
	go telegramBot.Start()

	router := mux.NewRouter()
	fmt.Println("Starting the application...")
	jwtSecret = os.Getenv("APP_JWT_SECRET")
	router.HandleFunc("/signup", SignUpEndpoint).Methods("POST")
	router.HandleFunc("/authenticate", CreateTokenEndpoint).Methods("POST")
	router.HandleFunc("/verify-otp/{otp}", VerifyOtpGetEndpoint).Methods("GET")
	router.HandleFunc("/jwt-refresh", RefreshJwtEndpoint).Methods("GET")
	router.HandleFunc("/protected", ValidateMiddleware(ProtectedEndpoint)).Methods("GET")
	router.HandleFunc("/set-email-note/{set-param}", ValidateMiddleware(SetEmailNoteEndpoint)).Methods("GET")
	router.HandleFunc("/set-telegram-note/{set-param}", ValidateMiddleware(SetTelegramNoteEndpoint)).Methods("GET")
	router.HandleFunc("/generate-secret", service.GenerateSecretEndpoint).Methods("GET")
	log.Fatal(http.ListenAndServe(":" + os.Getenv("APP_PORT"), router))
}
