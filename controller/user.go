package controller

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"image/png"
	"net/http"
	"net/mail"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	usererrors "github.com/grepvenancio/biblioteca/errors"
	"github.com/grepvenancio/biblioteca/model"
	"github.com/grepvenancio/biblioteca/utils"
	"github.com/grepvenancio/biblioteca/view"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func SignUpUserGet(w http.ResponseWriter, r *http.Request) {
	component := view.SignUpUserPage(model.UserSignUp{}, usererrors.FormError{})
	component.Render(r.Context(), w)
}

func SignUpUserPost(w http.ResponseWriter, r *http.Request) {
	var err error
	r.ParseForm()
	userSignUp, errors := utils.ParseUserSignUpForm(r)
	if len(errors) != 0 {
		component := view.SignUpUserPage(userSignUp, errors)
		component.Render(r.Context(), w)
		return
	}
	var user model.User

	user.Email = userSignUp.Email
	user.Name = userSignUp.Name
	user.EncryptedTOTPUrl = ""

	user.ID, _ = uuid.NewRandom()

	user.HashedPassword, _ = utils.HashPassword(userSignUp.Password)
	user.Role = []model.Role{model.UserRole}
	store := r.Context().Value("store").(*model.MemoryStore)

	confirmationToken, err := uuid.NewRandom()
	if err != nil {
		panic(err)
	}
	newPendingUser := model.PendingUser{
		User:              user,
		ConfirmationToken: confirmationToken,
		Exp:               time.Now().Add(2 * time.Hour),
	}
	fmt.Println(newPendingUser.ConfirmationToken)
	err = store.NewPendingUserRegistration(newPendingUser)
	if err != nil {
		component := view.ResultSignUpActionPage("pending",
			"Conta pendendo confirmação")
		component.Render(r.Context(), w)
		return
	}
	err = utils.SendConfirmationEmail(newPendingUser)
	if err != nil {
		component := view.ResultSignUpActionPage("fail",
			"Desculpe, tente mais tarde")
		component.Render(r.Context(), w)
		return
	}
	component := view.ResultSignUpActionPage("confirmation",
		"Um e-mail de confirmação foi enviado para sua caixa de mensagens, clicle nele para confirmar o seu cadastro.")
	component.Render(r.Context(), w)
	return
}

func ConfirmUserRegistration(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "Thu, 01 Jan 1970 00:00:00 GMT")
	session := r.Context().Value("session").(*scs.SessionManager)
	sessionData, ok := session.Get(r.Context(), "session-data").(bytes.Buffer)
	if ok {
		http.Redirect(w, r, "/user/home", http.StatusSeeOther)
		return
	}
	URLtoken := r.URL.Query().Get("token")
	token, err := uuid.Parse(URLtoken)
	fmt.Printf("token url: %s", token)

	if err != nil {
		http.Redirect(w, r, "/signup", http.StatusSeeOther)
		return
	}

	store := r.Context().Value("store").(*model.MemoryStore)

	user, err := store.ConfirmUserRegistration(token)
	if err != nil {
		fmt.Println(err.Error())
		if errors.Is(err, usererrors.ErrExpiredConfToken) {
			fmt.Println("entrando aqui")
			fmt.Println(user.Email)
			component := view.ResultSignUpActionPage("retry",
				user.Email)
			component.Render(r.Context(), w)
			return
		}
		component := view.ResultSignUpActionPage("fail",
			"desculpe tente mais tarde")
		component.Render(r.Context(), w)
		return
	}
	session = r.Context().Value("session").(*scs.SessionManager)
	data := model.SessionData{
		ID:   user.ID,
		Role: user.Role,
	}
	_ = gob.NewEncoder(&sessionData).Encode(data)
	session.Put(r.Context(), "session-data", sessionData.Bytes())
	http.Redirect(w, r, "/user/home", http.StatusSeeOther)
}

func EnableMFA(w http.ResponseWriter, r *http.Request) {
	store := r.Context().Value("store").(*model.MemoryStore)
	sessionData, ok := r.Context().Value("session-struct").(model.SessionData)
	if !ok {
		panic("hum?")
	}
	_, user := store.GetUser(sessionData.ID)
	if alreadyInProcess, ok := store.GetTOTPTicketPerUserId(
		sessionData.ID); ok {
		plaintext, _ := utils.DecryptAES(alreadyInProcess.EncryptedTOTPUrl)
		ticket, _ := otp.NewKeyFromURL(plaintext)
		view.TOTPConfirmationPage(
			ticket.Secret(), "", alreadyInProcess.Token.String()).Render(
			r.Context(), w)
		return
	}
	if user.EncryptedTOTPUrl != "" {
		//ALREDY HAVE MFA ENABLED
	}
	ticketID, _ := uuid.NewRandom()
	totpKey, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "biblioteca.com",
		AccountName: user.Email,
	})
	if err != nil {
		panic(err)
	}
	EncryptedUrl, err := utils.EncryptAES([]byte(totpKey.URL()))
	if err != nil {
		panic(err)
	}
	store.EnableTOTP(model.PendingTOTPConfirmation{
		Token:            ticketID,
		User:             *user,
		EncryptedTOTPUrl: EncryptedUrl,
	})
	fmt.Println("------------------------")
	fmt.Println(totpKey.URL())
	fmt.Println(EncryptedUrl)
	fmt.Println("------------------------")
	w.Header().Set("Hx-Push-Url", fmt.Sprintf(
		"/user/preferences/totp/%s", ticketID))
	view.TOTPConfirmationPage(
		totpKey.Secret(), "", ticketID.String()).Render(r.Context(), w)
}

func ConfirmTOTP(w http.ResponseWriter, r *http.Request) {
	fmt.Println("aqui")
	r.ParseForm()
	urlToken := chi.URLParam(r, "token")
	fmt.Println(urlToken)
	ticketID, err := uuid.Parse(urlToken)
	if err != nil {
		fmt.Println(urlToken)
		fmt.Println(err)
		http.Redirect(w, r, "/user/preferences", http.StatusSeeOther)
		return
	}
	fmt.Println("taaaar")
	code := r.FormValue("totp-code")
	store := r.Context().Value("store").(*model.MemoryStore)
	ticket, ok := store.GetPendingTOTPObject(ticketID)
	if !ok {
		fmt.Println("não achei")
		fmt.Println(urlToken)
		http.Redirect(w, r, "/user/preferences", http.StatusSeeOther)
		return
	}
	plaintext, _ := utils.DecryptAES(ticket.EncryptedTOTPUrl)
	fmt.Printf("url: %s", plaintext)
	key, err := otp.NewKeyFromURL(plaintext)
	if err != nil {
		panic(err)
	}
	if len(code) == 0 {
		fmt.Println("codigo vazio")
		view.TOTPConfirmationPage(
			key.Secret(),
			"Campo obrigatório",
			ticket.Token.String()).Render(r.Context(), w)
		return
	}
	valid := totp.Validate(code, key.Secret())
	if !valid {
		//RENDER ERRROR
		fmt.Println("codigo não valido")
		view.TOTPConfirmationPage(
			key.Secret(),
			"Código inválido",
			ticket.Token.String()).Render(r.Context(), w)
		return
	}
	err = store.ConfirmTOTP(ticket.Token)
	if err != nil {
		panic(err)
	}
	session := r.Context().Value("session").(*scs.SessionManager)
	sessionData := session.Get(r.Context(), "session-data")
	sessionDataBytes, _ := sessionData.([]byte)
	var sessionDataStruct model.SessionData
	buffer := bytes.NewBuffer(sessionDataBytes)
	_ = gob.NewDecoder(buffer).Decode(&sessionDataStruct)
	sessionDataStruct.HasMfa = true
	var dataBuffer bytes.Buffer
	_ = gob.NewEncoder(&dataBuffer).Encode(sessionDataStruct)
	session.Put(r.Context(), "session-data", dataBuffer.Bytes())
	session.Put(r.Context(), "flash", "totp habilitado")
	session.Destroy(r.Context())
	w.Header().Set("Hx-Push-Url", "/login")
	view.LoginPage(
		model.UserLogin{}, usererrors.FormError{}).Render(r.Context(), w)
}

func PreferencesGet(w http.ResponseWriter, r *http.Request) {
	view.PreferencesPage().Render(r.Context(), w)
}

func TOTPImage(w http.ResponseWriter, r *http.Request) {
	store := r.Context().Value("store").(*model.MemoryStore)
	sessionData, ok := r.Context().Value("session-struct").(model.SessionData)
	if !ok {
		panic("hum?")
	}
	ticket, ok := store.GetTOTPTicketPerUserId(sessionData.ID)
	if !ok {
		http.Redirect(w, r, "/preferences", http.StatusSeeOther)
	}
	fmt.Println(ticket.EncryptedTOTPUrl)
	plaintext, _ := utils.DecryptAES(ticket.EncryptedTOTPUrl)
	key, err := otp.NewKeyFromURL(plaintext)
	if err != nil {
		panic(err)
	}
	img, err := key.Image(600, 600)
	if err != nil {
		panic(err)
	}
	var buf bytes.Buffer
	png.Encode(&buf, img)
	imgBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	view.TOTPImage(imgBase64).Render(r.Context(), w)
}

func CancelTOTP(w http.ResponseWriter, r *http.Request) {
	tokenURL := chi.URLParam(r, "token")
	ticketID, err := uuid.Parse(tokenURL)
	if err != nil {
		http.Redirect(w, r, "/user/preferences", http.StatusSeeOther)
	}
	store := r.Context().Value("store").(*model.MemoryStore)
	err = store.CancelTOTPTicket(ticketID)
	if err != nil {
		http.Redirect(w, r, "/user/preferences", http.StatusSeeOther)
	}
	session := r.Context().Value("session").(*scs.SessionManager)
	session.Put(r.Context(), "flash", "habilitação de totp cancelada")
	w.Header().Set("Hx-Push-Url", "/user/preferences")
	view.PreferencesPage().Render(r.Context(), w)
}

func SignUpRetry(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	email := r.FormValue("email")
	if _, err := mail.ParseAddress(email); err != nil {
		fmt.Println(err)
		http.Redirect(w, r, "/signup", http.StatusSeeOther)
		return
	}
	newToken, _ := uuid.NewRandom()
	store := r.Context().Value("store").(*model.MemoryStore)
	pendingUser, err := store.UpdateConfirmationToken(email, newToken)
	if err != nil {
		component := view.ResultSignUpActionPage("fail",
			"bostejou patrão")
		component.Render(r.Context(), w)
		return
	}
	fmt.Printf("main\npendinguser=%s\nnewtoken=%s", pendingUser.ConfirmationToken, newToken)
	err = utils.SendConfirmationEmail(pendingUser)
	if err != nil {
		component := view.ResultSignUpActionPage("fail",
			"Deculpe tente mais tarde")
		component.Render(r.Context(), w)
		return
	}
	component := view.ResultSignUpActionPage("confirmation",
		"Um e-mail de confirmação foi enviado para sua caixa de mensagens, clicle nele para confirmar o seu cadastro.")
	component.Render(r.Context(), w)
	return
}

func UserHomePage(w http.ResponseWriter, r *http.Request) {
	component := view.UserHomePage()
	component.Render(r.Context(), w)
}

func LoginGet(w http.ResponseWriter, r *http.Request) {
	component := view.LoginPage(model.UserLogin{}, usererrors.FormError{})
	component.Render(r.Context(), w)
}

func LoginPost(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	userLogin, formErrors := utils.ParseUserLogin(r)
	if len(formErrors) != 0 {
		component := view.LoginPage(userLogin, formErrors)
		component.Render(r.Context(), w)
		return
	}
	store := r.Context().Value("store").(*model.MemoryStore)
	session := r.Context().Value("session").(*scs.SessionManager)
	ok, user := store.GetUserByEmail(userLogin.Email)
	if !ok || !utils.VerifyPassword(userLogin.Password, user.HashedPassword) {
		session.Put(r.Context(), "flash", "Credenciais inválidas")
		component := view.LoginPage(userLogin, formErrors)
		component.Render(r.Context(), w)
		return
	}
	hasMfa := false
	if user.EncryptedTOTPUrl != "" {
		hasMfa = true
	}
	data := model.SessionData{
		ID:         user.ID,
		Role:       user.Role,
		HasMfa:     hasMfa,
		PendingMFA: true,
	}
	var sessionData bytes.Buffer
	_ = gob.NewEncoder(&sessionData).Encode(data)
	session.Put(r.Context(), "session-data", sessionData.Bytes())
	session.Put(r.Context(), "redirect", "home")
	session.Put(r.Context(), "intent", "login")
	view.TOTPDialog("").Render(r.Context(), w)
}

func ConfirmEmailChange(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	urlToken := r.URL.Query().Get("token")
	ticketID, err := uuid.Parse(urlToken)
	session := r.Context().Value("session").(*scs.SessionManager)
	if err != nil {
		session.Put(r.Context(), "flash", "ticket invalido")
		view.UserHomePage().Render(r.Context(), w)
	}
	store := r.Context().Value("store").(*model.MemoryStore)
	ok, _ := store.ConfirmEmailChange(ticketID)
	if !ok {
		session.Put(r.Context(), "flash", "erro atualizando email")
		view.UserHomePage().Render(r.Context(), w)
	}
	session.Put(r.Context(), "flash", "email atualizado com sucesso")
	view.PreferencesPage().Render(r.Context(), w)
}

func VerifyMFA(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	code := r.FormValue("totp-code")
	userSession, ok := r.Context().Value("session-struct").(model.SessionData)
	if !ok {
		panic("ok...")
	}
	fmt.Printf("session do user: %v", userSession)
	fmt.Println("aqui")
	store := r.Context().Value("store").(*model.MemoryStore)
	fmt.Println("aqui2")
	session := r.Context().Value("session").(*scs.SessionManager)
	intent := session.Get(r.Context(), "intent").(string)
	fmt.Println("aqui3")
	_, user := store.GetUser(userSession.ID)
	fmt.Println("aqui4")
	if (!userSession.HasMfa ||
		(userSession.HasMfa && !userSession.PendingMFA)) &&
		intent == "login" {
		http.Redirect(w, r, "/user/home", http.StatusSeeOther)
		return
	}
	fmt.Println("aqui5")
	if len(code) == 0 {
		view.TOTPInput("Campo obrigatório").Render(r.Context(), w)
		return
	}
	fmt.Println("aqui6")
	plaintext, _ := utils.DecryptAES(user.EncryptedTOTPUrl)
	key, _ := otp.NewKeyFromURL(plaintext)
	fmt.Println("aqui7")
	valid := totp.Validate(code, key.Secret())
	fmt.Println("aqui8")
	if !valid {
		view.TOTPInput("Código inválido").Render(r.Context(), w)
		return
	}
	fmt.Println("aqui9")
	userSession.PendingMFA = false
	var sessionData bytes.Buffer
	_ = gob.NewEncoder(&sessionData).Encode(userSession)
	session.Put(r.Context(), "session-data", sessionData.Bytes())
	if !ok {
		http.Redirect(w, r, "/user/home", http.StatusSeeOther)
		return
	}
	_ = session.Pop(r.Context(), "intent").(string)
	_ = session.Pop(r.Context(), "redirect").(string)
	if intent == "login" {
		w.Header().Set("HX-Replace-Url", "/user/home")
		w.Header().Set("Hx-Retarget", "#main")
		view.UserHomePage().Render(r.Context(), w)
	} else if intent == "email-pref" {
		var user model.User
		draftedBytes := session.Pop(r.Context(), "drafted-user").([]byte)
		userbuf := bytes.NewBuffer(draftedBytes)
		_ = gob.NewDecoder(userbuf).Decode(&user)
		_, oldUser := store.GetUser(user.ID)
		ticketID, _ := uuid.NewRandom()
		emailChange := model.PendindEmailChange{
			TicketID: ticketID,
			UserID:   user.ID,
			OldEmail: oldUser.Email,
			NewEmail: user.Email,
		}
		_ = utils.ChangingEmail(emailChange)
		store.NewPendingEmailChange(emailChange)
		w.Header().Set("Hx-Push-Url", "/user/preferences")
		w.Header().Set("Hx-Retarget", "#totp-dialog")
		w.Header().Set("Hx-Reswap", "outerHTML")
		fmt.Fprint(w, "")
	}
}

func RecoverPasswordGet(w http.ResponseWriter, r *http.Request) {
	view.PasswordRecoveryRequestPage("", usererrors.FormError{}).Render(
		r.Context(), w)
}

func RecoverPasswordPost(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	store := r.Context().Value("store").(*model.MemoryStore)
	session := r.Context().Value("session").(*scs.SessionManager)
	if urlToken := r.URL.Query().Get("ticket"); urlToken != "" {
		ticket, err := uuid.Parse(urlToken)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		pinCode, err := utils.ParsePinCode(r)
		if err != nil {
			session.Put(r.Context(), "flash", "PIN inválido")
			view.PasswordPinRecoverPage(ticket).Render(r.Context(), w)
			return
		}
		status, err := store.TicketStatus(ticket)
		if status == model.RecoverAwaitingPin {
			ok, err := store.VerifyPin(ticket, pinCode)
			if err != nil {
				if errors.Is(err, usererrors.ErrTicketExpired) {
					view.PasswordRecoveryRetryPage(ticket).Render(
						r.Context(), w)
					return
				} else {
					http.Redirect(w, r, "/login", http.StatusSeeOther)
					return
				}
			}
			if !ok {
				session.Put(r.Context(), "flash", "PIN inválido")
				view.PasswordPinRecoverPage(ticket).Render(r.Context(), w)
				return
			}
			ticketObj, _ := store.UpgradeStatus(ticket)
			view.PasswordRecoveryPage(
				model.PasswordRecoverUser{
					Ticket: ticketObj.Ticket,
				},
				usererrors.FormError{},
				pinCode).Render(r.Context(), w)
			return
		} else if status == model.RecoverResetPasswd {
			passwdRecUser, formErr := utils.ParseRecoverPasswordForm(r)
			if len(formErr) != 0 {
				view.PasswordRecoveryPage(
					passwdRecUser, formErr, pinCode).Render(
					r.Context(), w)
				return
			}
			hashedPasswd, _ := utils.HashPassword(passwdRecUser.Password)
			err := store.ResetPassword(ticket, pinCode, hashedPasswd)
			if err != nil {
				if errors.Is(err, usererrors.ErrTicketExpired) {
					view.PasswordRecoveryRetryPage(ticket).Render(
						r.Context(), w)
					return
				} else if errors.Is(err, usererrors.ErrInvalidPin) ||
					errors.Is(err, usererrors.ErrPinNotFound) {
					session.Put(r.Context(), "flash", "PIN inválido")
					view.PasswordPinRecoverPage(ticket).Render(
						r.Context(), w)
					return
				} else {
					http.Redirect(w, r, "/login", http.StatusSeeOther)
					return
				}
			}
			session.Put(r.Context(), "flash", "Senha atualizada")
			w.Header().Set("Hx-Push-Url", "/login")
			view.LoginPage(
				model.UserLogin{}, usererrors.FormError{}).Render(
				r.Context(), w)
			return
		}
	}
	email, formErr := utils.ParseEmail(r)
	if len(formErr) != 0 {
		view.PasswordRecoveryRequestPage(
			email, formErr).Render(r.Context(), w)
		return
	}
	pinCode, _ := utils.GenPinCode(6)
	ok, user := store.GetUserByEmail(email)
	ticket, _ := uuid.NewRandom()
	if ok {
		store.NewPasswordRecoveryTicket(model.PasswordRecoverTicket{
			Ticket: ticket,
			User:   *user,
			Pin:    pinCode,
			Exp:    time.Now().Add(2 * time.Minute),
			Status: model.RecoverAwaitingPin,
		})
		utils.SendPinCode(user.Email, pinCode)
	}
	w.Header().Set("HX-Push-Url", fmt.Sprintf(
		"/login/recover?ticket=%s", ticket))
	view.PasswordPinRecoverPage(ticket).Render(r.Context(), w)
}

func RetryPasswordRecover(w http.ResponseWriter, r *http.Request) {
	urlToken := r.URL.Query().Get("ticket")
	ticket, err := uuid.Parse(urlToken)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
	store := r.Context().Value("store").(*model.MemoryStore)
	newPin, _ := utils.GenPinCode(6)
	ticketObject, err := store.GenerateNewPin(ticket, newPin)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
	utils.SendPinCode(ticketObject.User.Email, newPin)
	w.Header().Set("Hx-Push-Url", fmt.Sprintf("/login/recover?ticket=%s", ticket))
	view.PasswordPinRecoverPage(ticket).Render(r.Context(), w)
}

func ChangeName(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	userSession := r.Context().Value("session-struct").(model.SessionData)
	store := r.Context().Value("store").(*model.MemoryStore)
	_, user := store.GetUser(userSession.ID)
	newName, formErr := utils.ParseName(r)
	if len(formErr) != 0 {
		view.NamePreferences(newName, formErr["name"]).Render(
			r.Context(), w)
		return
	}
	user.Name = newName
	_ = store.UpdateUser(userSession.ID, *user)
	// RENDER WITH UPDATED NAME
	view.NamePreferences("", "").Render(
		r.Context(), w)
	return
}

func ChangeEmail(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	userSession := r.Context().Value("session-struct").(model.SessionData)
	store := r.Context().Value("store").(*model.MemoryStore)
	session := r.Context().Value("session").(*scs.SessionManager)
	_, user := store.GetUser(userSession.ID)
	newEmail, formErr := utils.ParseEmail(r)
	if len(formErr) != 0 {
		view.EmailPreferences(newEmail, formErr["email"]).Render(
			r.Context(), w)
		return
	}
	user.Email = newEmail
	var draftedBuf bytes.Buffer
	_ = gob.NewEncoder(&draftedBuf).Encode(*user)
	session.Put(r.Context(), "redirect", "preferences")
	session.Put(r.Context(), "intent", "email-pref")
	session.Put(r.Context(), "drafted-user", draftedBuf.Bytes())
	view.TOTPDialog("").Render(r.Context(), w)
}

func ChangePassword(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	userSession := r.Context().Value("session-struct").(model.SessionData)
	store := r.Context().Value("store").(*model.MemoryStore)
	_, user := store.GetUser(userSession.ID)
	newEmail, formErr := utils.ParseEmail(r)
	if len(formErr) != 0 {
		// RENDER ERROR
	}
	user.Email = newEmail
	_ = store.UpdateUser(userSession.ID, *user)
	// RENDER WITH UPDATED NAME
}
