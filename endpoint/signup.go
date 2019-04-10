package endpoint

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/Auth2FA/model"
	"github.com/Auth2FA/service"
	"github.com/jinzhu/gorm"
)

type newUser struct {
	FirstName    string `json:"firstname"`
	LastName     string `json:"lastname"`
	Email        string `json:"email"`
	Phone        string `json:"phone"`
	Password     string `json:"password"`
	ConfPassword string `json:"confpassword"`
	ChatID       int64  `json:"chatid"`
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
			Phone:          userPhone,
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
