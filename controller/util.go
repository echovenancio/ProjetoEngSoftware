package controller

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/a-h/templ"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/grepvenancio/biblioteca/model"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	passwordvalidator "github.com/wagslane/go-password-validator"
	"golang.org/x/crypto/argon2"
)

func getErrorMsg(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "campo obrigatório"
	case "isbn10":
		return "isbn inválido"
	case "email":
		return "email inválido"
	case "entropy":
		return "senha muito fraca"
	}
	return "erro"
}

func location(c *gin.Context, path string) {
	c.Header("HX-Location", path)
}

func render(
	c *gin.Context,
	component templ.Component,
	code int,
	params ...string) {
	if len(params) == 1 {
		c.Header("HX-Reswap", params[0])
	} else if len(params) == 2 {
		c.Header("HX-Reswap", params[0])
		c.Header("HX-Retarget", params[1])
	}
	c.Status(200)
	component.Render(c, c.Writer)
}

func verifyPassword(passwd, encodedHash string) bool {
	parts := strings.Split(encodedHash, ":")
	salt, _ := base64.RawStdEncoding.DecodeString(parts[0])
	expHash, _ := base64.RawStdEncoding.DecodeString(parts[1])
	hash := argon2.IDKey([]byte(passwd), salt, 1, 64*1024, 4, 32)
	if subtle.ConstantTimeCompare(hash, expHash) == 1 {
		return true
	}
	return false
}

func verifyTOTP(c *gin.Context) error {
	var totpInput struct {
		Code string `form:"totp-code" binding:"required,len=6,numeric"`
	}
	err := c.ShouldBind(&totpInput)
	if err != nil {
		var ve validator.ValidationErrors
		if errors.As(err, &ve) {
			err := getErrorMsg(ve[0])
			return fmt.Errorf(err)
		}
	}
	session := sessions.Default(c)
	data := getSessionData(session)
	store := c.MustGet("store").(*model.MemoryStore)
	user, _ := store.GetUser(data.UserID)
	plaintext, _ := decryptAES(user.EncryptedTOTPUrl)
	key, _ := otp.NewKeyFromURL(plaintext)
	valid := totp.Validate(totpInput.Code, key.Secret())
	if !valid {
		return fmt.Errorf("Código inválido")
	}
	fmt.Println("aqui9")
	return nil
	// if intent == "login" {
	// 	w.Header().Set("HX-Replace-Url", "/user/home")
	// 	w.Header().Set("Hx-Retarget", "#main")
	// 	view.UserHomePage().Render(r.Context(), w)
	// } else if intent == "email-pref" {
	// 	var user model.User
	// 	draftedBytes := session.Pop(r.Context(), "drafted-user").([]byte)
	// 	userbuf := bytes.NewBuffer(draftedBytes)
	// 	_ = gob.NewDecoder(userbuf).Decode(&user)
	// 	_, oldUser := store.GetUser(user.ID)
	// 	ticketID, _ := uuid.NewRandom()
	// 	emailChange := model.PendindEmailChange{
	// 		TicketID: ticketID,
	// 		UserID:   user.ID,
	// 		OldEmail: oldUser.Email,
	// 		NewEmail: user.Email,
	// 	}
	// 	_ = utils.ChangingEmail(emailChange)
	// 	store.NewPendingEmailChange(emailChange)
	// 	w.Header().Set("Hx-Push-Url", "/user/preferences")
	// 	w.Header().Set("Hx-Retarget", "#totp-dialog")
	// 	w.Header().Set("Hx-Reswap", "outerHTML")
	// 	fmt.Fprint(w, "")
	// }
}

func encryptAES(plaintext []byte) (string, error) {
	key, ok := os.LookupEnv("AES_SECRET")
	if !ok {
		panic("unable to find aes key")
	}
	fmt.Println(len([]byte(key)))
	fmt.Printf("Chave: %s", key)
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return string(ciphertext), nil
}

func decryptAES(data string) (string, error) {
	key, ok := os.LookupEnv("AES_SECRET")
	if !ok {
		panic("unable to find aes key")
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	nonce, cipher := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, []byte(nonce), []byte(cipher), nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func getSessionData(session sessions.Session) model.SessionData {
	jsonData := session.Get("session-data")
	var data model.SessionData
	_ = json.Unmarshal(jsonData.([]byte), &data)
	return data
}

func setSessionData(session sessions.Session, data model.SessionData) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	session.Set("session-data", jsonData)
	return nil
}

func hashPassword(passwd string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}
	hash := argon2.IDKey([]byte(passwd), salt, 1, 64*1024, 4, 32)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	return fmt.Sprintf("%s:%s", b64Salt, b64Hash), nil
}

func normalizeInputField(field string) string {
	return strings.Replace(strings.ToLower(field), " ", "-", -1)
}
