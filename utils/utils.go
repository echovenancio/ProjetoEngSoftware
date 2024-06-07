package utils

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	netmail "net/mail"
	"os"
	"strconv"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v5"
	usererrors "github.com/grepvenancio/biblioteca/errors"
	"github.com/grepvenancio/biblioteca/model"
	"gopkg.in/mail.v2"
)

const minEntropyBits = 60

func SendConfirmationEmail(pendingUser model.PendingUser) error {
}

func ChangingEmail(pendingEmailChange model.PendindEmailChange) error {
	dialerHost := os.Getenv("DIALER_HOST")
	dialerPort, err := strconv.Atoi(os.Getenv("DIALER_PORT"))
	if err != nil {
		panic("Error getting dialer port.")
	}
	dialerUsername := os.Getenv("DIALER_USERNAME")
	dialerPassword := os.Getenv("DIALER_PASSWORD")
	m := mail.NewMessage()
	confirmationURL := fmt.Sprintf(
		"http://localhost:8080/user/preferences/email/confirm?token=%s",
		pendingEmailChange.TicketID)
	m.SetHeader("From", "no-reply@biblioteca.com")
	m.SetHeader("To", pendingEmailChange.NewEmail)
	m.SetHeader("Subject", "Mudança de email")
	m.SetBody("text/plain", fmt.Sprintf(
		"click no link para confirmar a atualização de email, de: %s, para: %s, %s",
		pendingEmailChange.OldEmail,
		pendingEmailChange.NewEmail,
		confirmationURL))
	d := mail.NewDialer(
		dialerHost, dialerPort, dialerUsername, dialerPassword)
	err = d.DialAndSend(m)
	m.SetHeader("From", "no-reply@biblioteca.com")
	m.SetHeader("To", pendingEmailChange.OldEmail)
	m.SetHeader("Subject", "Mudança de email")
	m.SetBody("text/plain", fmt.Sprintf(
		"Atualizando email, de: %s, para: %s",
		pendingEmailChange.OldEmail, pendingEmailChange.NewEmail))
	d = mail.NewDialer(
		dialerHost, dialerPort, dialerUsername, dialerPassword)
	err = d.DialAndSend(m)
	return err
}

func SendPinCode(email string, pinCode string) error {
	dialerHost := os.Getenv("DIALER_HOST")
	dialerPort, err := strconv.Atoi(os.Getenv("DIALER_PORT"))
	if err != nil {
		panic("Error getting dialer port.")
	}
	dialerUsername := os.Getenv("DIALER_USERNAME")
	dialerPassword := os.Getenv("DIALER_PASSWORD")
	m := mail.NewMessage()
	m.SetHeader("From", "no-reply@biblioteca.com")
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Recuperar senha")
	m.SetBody("text/plain", fmt.Sprintf(
		"Recupere a sua senha com o pin: %s", pinCode))
	d := mail.NewDialer(dialerHost, dialerPort, dialerUsername, dialerPassword)
	err = d.DialAndSend(m)
	return err
}

func GenerateConfirmationToken(email string) string {
	hmacSecret, exists := os.LookupEnv("HMAC_SECRET")
	if !exists {
		panic("Unable to find hmac secret")
	}
	claims := model.JwtConfirmationTokenClaims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(2 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(hmacSecret))
	fmt.Println(tokenString, err)
	return tokenString
}

func VerifyConfirmationToken(tokenString string) (string, error) {
	hmacSecret, exists := os.LookupEnv("HMAC_SECRET")
	if !exists {
		panic("Unable to find hmac secret")
	}
	token, err := new(jwt.Parser).ParseWithClaims(
		tokenString,
		&model.JwtConfirmationTokenClaims{},
		func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return []byte(hmacSecret), nil
		})

	if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
		return "", err
	}

	claims, ok := token.Claims.(*model.JwtConfirmationTokenClaims)

	if !ok {
		return "", jwt.ErrTokenInvalidClaims
	}

	if claims.ExpiresAt.Time.Before(time.Now()) {
		return claims.Email, jwt.ErrTokenExpired
	}

	return claims.Email, nil
}

func CheckEmail(email string, formError usererrors.FormError) {
	if _, err := netmail.ParseAddress(email); err != nil {
		formError["email"] = "e-mail inválido"
	}
}

func ParseEmail(r *http.Request) (string, usererrors.FormError) {
	formError := make(usererrors.FormError)
	checkRequiredField := func(field, value string) {
		if value == "" {
			formError[field] = "Campo de prenchimento obrigatório"
		}
	}
	email := r.FormValue("email")
	CheckEmail(email, formError)
	checkRequiredField("email", email)

	return email, formError
}

func ParseUserLogin(r *http.Request) (model.UserLogin, usererrors.FormError) {
	var user model.UserLogin
	formError := make(usererrors.FormError)

	checkRequiredField := func(field, value string) {
		if value == "" {
			formError[field] = "Campo de prenchimento obrigatório"
		}
	}

	user.Email = r.FormValue("email")
	checkRequiredField("email", user.Email)
	CheckEmail(user.Email, formError)

	user.Password = r.FormValue("passwd")
	checkRequiredField("passwd", user.Password)

	return user, formError
}

func ParseUserSignUpForm(r *http.Request) (
	model.UserSignUp, usererrors.FormError) {
	var user model.UserSignUp
	formError := make(usererrors.FormError)

	checkRequiredField := func(field, value string) {
		if value == "" {
			formError[field] = "Campo de prenchimento obrigatório"
		}
	}

	checkPasswordEq := func(passwd, confPasswd string) {
		if passwd != confPasswd {
			formError["confpasswd"] = "A senha precisa ser igual"
		}
	}

	user.Name = r.FormValue("name")
	checkRequiredField("name", user.Name)

	user.Email = r.FormValue("email")
	checkRequiredField("email", user.Email)
	CheckEmail(user.Email, formError)

	user.Password = r.FormValue("passwd")
	CheckPasswordEntropyAndSize(user.Password, formError)
	checkRequiredField("passwd", user.Password)
	checkPasswordEq(user.Password, r.FormValue("confpasswd"))

	return user, formError
}

func ParseRecoverPasswordForm(r *http.Request) (
	model.PasswordRecoverUser, usererrors.FormError) {
	var user model.PasswordRecoverUser
	formError := make(usererrors.FormError)

	checkRequiredField := func(field, value string) {
		if value == "" {
			formError[field] = "Campo de prenchimento obrigatório"
		}
	}

	checkPasswordEq := func(passwd, confPasswd string) {
		if passwd != confPasswd {
			formError["confpasswd"] = "A senha precisa ser igual"
		}
	}

	user.Password = r.FormValue("passwd")
	checkRequiredField("passwd", user.Password)
	CheckPasswordEntropyAndSize(user.Password, formError)

	user.ConfitmationPassword = r.FormValue("confpasswd")
	checkRequiredField("confpasswd", user.ConfitmationPassword)
	checkPasswordEq(user.Password, r.FormValue("confpasswd"))

	return user, formError
}

func ParseName(r *http.Request) (string, usererrors.FormError) {
	formError := make(usererrors.FormError)
	checkRequiredField := func(field, value string) {
		if value == "" {
			formError[field] = "Campo de prenchimento obrigatório"
		}
	}
	nome := r.FormValue("name")
	CheckEmail(nome, formError)
	checkRequiredField("name", nome)

	return nome, formError
}

func ParseBookForm(r *http.Request) (model.Book, usererrors.FormError) {
	var book model.Book
	formError := make(usererrors.FormError)

	checkRequiredField := func(field, value string) {
		if value == "" {
			formError[field] = "Campo de prenchimento obrigatório"
		}
	}

	book.Isbn = r.FormValue("isbn")
	checkRequiredField("isbn", book.Isbn)

	book.Author = r.FormValue("author")
	checkRequiredField("author", book.Author)

	book.Title = r.FormValue("title")
	checkRequiredField("title", book.Title)

	book.Publisher = r.FormValue("publisher")
	checkRequiredField("publisher", book.Publisher)

	book.Genre = r.FormValue("genre")
	checkRequiredField("genre", book.Genre)

	if pages := r.FormValue("pages"); pages != "" {
		qtPag, err := strconv.Atoi(pages)
		if err != nil || qtPag <= 0 {
			formError["pages"] = "Valor precisa ser um número maior que zero"
		} else {
			book.Pages = qtPag
		}
	} else {
		formError["pages"] = "Campo de prenchimento obrigatório"
	}

	if len(formError) > 0 {
		return book, formError
	}

	return book, nil
}

func GenPinCode(length int) (string, error) {
	max := int64(1)
	for i := 0; i < length; i++ {
		max *= 10
	}
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return "", err
	}
	format := "%0" + strconv.Itoa(length) + "d"
	return fmt.Sprintf(format, n), nil
}

func ParsePinCode(r *http.Request) (string, error) {
	pin := r.FormValue("pin")
	fmt.Println(pin)
	if len(pin) != 6 || hasLetter(pin) {
		return "", usererrors.ErrInvalidPin
	}
	return pin, nil
}

func hasLetter(input string) bool {
	for _, ch := range input {
		if unicode.IsLetter(ch) {
			return true
		}
	}
	return false
}
