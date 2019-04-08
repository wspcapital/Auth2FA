package model

import (
	"time"
)

type User struct {
	ID                int
	ChatID            int64
	Alias             string
	Email             string
	Phone             int64
	Passw             string
	FirstName         string
	LastName          string
	Active            bool
	Role              int
	Salt              string
	TwoFactorEmail    bool
	TwoFactorTelegram bool
    TelegramKeyToken  string
	SessionKey        string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}
