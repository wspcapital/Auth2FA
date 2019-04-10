package service

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"github.com/go-telegram-bot-api/telegram-bot-api"
	"github.com/jinzhu/gorm"
	"fmt"
	"github.com/batonych/copier/model"
)

type TelegramBot struct {
	API                   *tgbotapi.BotAPI
	Updates               tgbotapi.UpdatesChannel
}

func SendOtpByTelegram(chat_id int64, otp string) bool {
	body := strings.NewReader("chat_id=" + strconv.FormatInt(chat_id, 10) + "&text=" + otp)

	req, err := http.NewRequest("POST", "https://api.telegram.org/bot"+os.Getenv("BOT_API_KEY")+"/sendMessage", body)
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return true
}

func (telegramBot *TelegramBot) Init() error  {

	botAPI, err := tgbotapi.NewBotAPI(os.Getenv("BOT_API_KEY"))
	if err != nil {
		return err
	}
	var user model.User

	if err !=nil {
		fmt.Print(err.Error())
	} else {
		fmt.Print(user.Email)
	}

	telegramBot.API = botAPI
	botUpdate := tgbotapi.NewUpdate(0)
	botUpdate.Timeout = 60
	botUpdates, err := telegramBot.API.GetUpdatesChan(botUpdate)
	if err != nil {
		return err
	}
	telegramBot.Updates = botUpdates
	botUpdates.Clear()
	fmt.Println("Bot Init")
	return nil
}

func (telegramBot *TelegramBot) Start() {
	for {
		select {
		case update := <-telegramBot.Updates:
			chatID := update.Message.Chat.ID

			if update.Message.IsCommand() {
				requestMessage := tgbotapi.NewMessage(chatID, "Hello, to verification You need indicate Telegram Verification Token")
				result, _ := telegramBot.API.Send(requestMessage)
				fmt.Println(result)
			} else if update.Message != nil {
				var user model.User
				err := DB.Connect.Table("users").
					Select("users.email, users.passw, users.salt, users.chat_id").
					Where("users.telegram_key_token = ?", update.Message.Text).First(&user).Error

				if err == nil {
					if err := DB.Connect.Model(&user).Update(map[string]interface{}{"chat_id":chatID,"two_factor_telegram":true}).Error; err == nil {
						requestMessage := tgbotapi.NewMessage(chatID, "Telegram Authorization is successfully")
						result, _ := telegramBot.API.Send(requestMessage)
						fmt.Println(result)
					} else {
						requestMessage := tgbotapi.NewMessage(chatID, "Telegram Authorization wrong, try again")
						result, _ := telegramBot.API.Send(requestMessage)
						fmt.Println(result)
					}
				} else if gorm.IsRecordNotFoundError(err) == true {
					requestMessage := tgbotapi.NewMessage(chatID, "Telegram Authorization Token is incorrect")
					result, _ := telegramBot.API.Send(requestMessage)
					fmt.Println(result)
				}
			}
		}
	}
}
