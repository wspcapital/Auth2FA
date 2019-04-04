package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/batonych/copier/model"
	"github.com/batonych/copier/service"
	"os"
	"time"

	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/joho/godotenv"
)

var DBConnect *gorm.DB

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
		err = DBConnect.Table("users").
			Select("users.email, users.passw, users.salt, users.chat_id").
			Where("users.id =  ? and users.passw = ?", decodedToken["user_id"], decodedToken["password"]).First(&user).Error

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
	if err := DBConnect.Table("users").
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

	authUser := make(map[string]interface{})
	authUser["expiresIn"] = time.Now().Add(time.Second * 3600).Unix()
	authUser["user_id"] = user.ID
	authUser["password"] = user.Passw
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
	err = DBConnect.Table("users").
		Select("users.email, users.passw, users.salt, users.chat_id").
		Where("users.id =  ? and users.passw = ?", decodedToken["user_id"], decodedToken["password"]).First(&user).Error

	if err != nil && gorm.IsRecordNotFoundError(err) == true {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode("JWT is incorrect")
		return
	} else if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(err.Error())
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
		decodedToken["authorized"] = true
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
	err = DBConnect.Table("users").
		Select("users.email, users.passw, users.salt, users.chat_id").
		Where("users.id =  ? and users.passw = ?", decodedToken["user_id"], decodedToken["password"]).First(&user).Error

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

	decodedToken["expiresIn"] = time.Now().Add(time.Second * 3600).Unix()
	jwToken, _ := service.SignJwt(decodedToken, jwtSecret)
	json.NewEncoder(w).Encode(jwToken)
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
	err := DBConnect.Table("users").
		Select("users.email, users.passw, users.salt, users.chat_id").
		Where("users.email =  ?", u.Email).First(&user).Error

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
			Salt:           salt,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
			ChatID:         u.ChatID,
			TwoFactorEmail: true,
		}

		if err := DBConnect.Create(&User).Error; err != nil {
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
	w.Write([]byte("Email " + user.Email + " is used"))
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

		if err := DBConnect.First(&user, int(mapJWT["user_id"].(float64))).Error; err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(err.Error())
			return
		}

		if user.TwoFactorEmail != setParam {
			user.TwoFactorEmail = setParam

			if err := DBConnect.Save(&user).Error; err != nil {
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
		if err := DBConnect.First(&user, int(mapJWT["user_id"].(float64))).Error; err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(err.Error())
			return
		}

		if user.ChatID == 0 {
			user.TelegramKeyToken = service.GetRandomString(24)

			if err := DBConnect.Save(&user).Error; err != nil {
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

			if err := DBConnect.Save(&user).Error; err != nil {
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
	db, err := gorm.Open("postgres",
		"host="+os.Getenv("DB_HOST")+" port="+os.Getenv("DB_PORT")+" user="+os.Getenv("DB_USER")+" dbname="+os.Getenv("DB_NAME")+" password="+os.Getenv("DB_PSW"))
	DBConnect = db
	if err != nil {
		panic(err)
	}
	defer db.Close()

	telegramBot.Init(db)
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
	log.Fatal(http.ListenAndServe(":8080", router))
}