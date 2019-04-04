package service

import (
	"regexp"
	"strings"
	"net/http"
	"os"
)

func SendOtpByCurlEmail(recipient string, otp string) (bool, error) {

	body := strings.NewReader(` {
	"personalizations": [
		{
			"to": [
				{
					"email": "` + recipient + `"
				}
			],
			"subject": "OTP"
		}
	],
	"from": {
		"email": "wspdev@gmail.com"
	},
	"content": [
		{
			"type": "text/plain",
			"value": "` + otp + `"
		}
	]
}`)

	req, err := http.NewRequest("POST", "https://api.sendgrid.com/v3/mail/send", body)
	if err != nil {
		return false,err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer " + os.Getenv("SG_API_KEY"))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false,err
	}
	defer resp.Body.Close()

	return true, nil
}

/*func SendOtpByEmail(recipient string, otp string) (bool, error) {

	auth := smtp.PlainAuth(
		"",
		os.Getenv("EMAIL_USER"), //email
		os.Getenv("EMAIL_PSW"),  //email pass
		os.Getenv("EMAIL_HOST"),
	)
	msg := []byte("To: " +
		recipient + "\r\n" +
		"Subject: 2FA\r\n" +
		"\r\n" + otp + "\r\n")
	err := smtp.SendMail(
		os.Getenv("EMAIL_ADDR")+":"+os.Getenv("EMAIL_PORT"),
		auth,
		os.Getenv("EMAIL_USER"),
		[]string{recipient},
		msg,
	)
	if err != nil {
		fmt.Println(err)
		return false, fmt.Errorf("error send mail: %v\n", err)
	}

	return true, nil
}*/

func ValidateEmail(email string) bool {
	Re := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	return Re.MatchString(email)
}
