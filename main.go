package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"os"
	"time"

	"github.com/Auth2FA/model"
	"github.com/Auth2FA/service"

	"github.com/Auth2FA/endpoint"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/joho/godotenv"
)

func ValidateMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
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

func main() {
	err := godotenv.Load()

	err = service.DB.Init()

	if err != nil {
		panic(err)
	}
	defer service.DB.Connect.Close()

	var telegramBot service.TelegramBot
	telegramBot.Init()
	go telegramBot.Start()

	router := mux.NewRouter()
	fmt.Println("Starting the application...")
	service.JWTSecret = os.Getenv("APP_JWT_SECRET")

	router.HandleFunc("/signup", endpoint.SignUpEndpoint).Methods("POST")

	router.HandleFunc("/authenticate", endpoint.CreateTokenEndpoint).Methods("POST")

	router.HandleFunc("/verify-otp/{otp}", endpoint.VerifyOtpGetEndpoint).Methods("GET")

	router.HandleFunc("/jwt-refresh", endpoint.RefreshJwtEndpoint).Methods("GET")

	router.HandleFunc("/protected", ValidateMiddleware(endpoint.ProtectedEndpoint)).Methods("GET")

	router.HandleFunc("/set-email-note/{set-param}", ValidateMiddleware(endpoint.SetEmailNoteEndpoint)).Methods("GET")

	router.HandleFunc("/set-telegram-note/{set-param}", ValidateMiddleware(endpoint.SetTelegramNoteEndpoint)).Methods("GET")

	router.HandleFunc("/generate-secret", service.GenerateSecretEndpoint).Methods("GET")

	log.Fatal(http.ListenAndServe(":"+os.Getenv("APP_PORT"), router))
}
