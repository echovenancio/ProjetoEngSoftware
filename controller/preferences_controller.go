package controller

import (
	"errors"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/grepvenancio/biblioteca/model"
	"github.com/grepvenancio/biblioteca/model/action"
	"github.com/grepvenancio/biblioteca/view"
	"github.com/grepvenancio/biblioteca/view/components"
	"github.com/pquerna/otp"
)

func ChangeName(c *gin.Context) {
	var form struct {
		Name string `form:"name" binding:"required"`
	}
	session := sessions.Default(c)
	data := getSessionData(session)
	store := c.MustGet("store").(*model.MemoryStore)
	user, _ := store.GetUser(data.UserID)
	err := c.ShouldBind(&form)
	if err != nil {
		var ve validator.ValidationErrors
		if errors.As(err, ve) {
			var err string
			for _, fe := range ve {
				err = getErrorMsg(fe)
			}
			component := view.NamePreferences(form.Name, err)
			render(c, component, 400, "outerHTML")
		}
	}
	user.Name = form.Name
	_ = store.UpdateUser(data.UserID, user)
	component := view.ResourceUpdated("nome")
	render(c, component, 204, "afterbegin")
}

func ChangeEmail(c *gin.Context) {
	if c.GetHeader("HX-Trigger") == "totp-dialog" {
		err := verifyTOTP(c)
		if err != nil {
			component := view.TOTPInput(err.Error())
			render(c, component, 400)
			return
		}
		session := sessions.Default(c)
		actionID := session.Get("action").(string)
		actionStore := c.MustGet("action-store").(*action.ActionStore)
		store := c.MustGet("action").(*model.MemoryStore)
		retAction, ok := actionStore.Pop(uuid.MustParse(actionID))
		if !ok || !retAction.IsValid() {
			component := components.Empty()
			render(c, component, 400, "outerHTML", "totp-dialog")
			return
		}
		draft, ok := retAction.Draft.(model.User)
		if retAction.Type != action.UserUpdateAttempt || !ok {
			panic("not login draft")
		}
		store.UpdateUser(draft.ID, draft)
		component := view.ResourceUpdated("email")
		render(c, component, 204, "afterbegin")
		return
	}
	var form struct {
		Email string `form:"email" binding:"required, email"`
	}
	session := sessions.Default(c)
	store := c.MustGet("action-store").(*model.MemoryStore)
	err := c.ShouldBind(&form)
	if err != nil {
		var ve validator.ValidationErrors
		if errors.As(err, &ve) {
			var err string
			for _, fe := range ve {
				err = getErrorMsg(fe)
			}
			component := view.EmailPreferences(form.Email, err)
			render(c, component, 400, "outerHTML")
			return
		}
	}
	data := getSessionData(session)
	user, _ := store.GetUser(data.UserID)
	user.Email = form.Email
	emailChangeAction := action.NewUserUpdateAttempt(user)
	session.Set("action", emailChangeAction.ID.String())
	component := view.TOTPDialog("/user/preferences/email")
	render(c, component, 200, "afterbegin")
}

func ChangePassword(c *gin.Context) {
	if c.GetHeader("HX-Trigger") == "totp-dialog" {
		err := verifyTOTP(c)
		if err != nil {
			component := view.TOTPInput(err.Error())
			render(c, component, 400)
			return
		}
		session := sessions.Default(c)
		actionID := session.Get("action").(string)
		actionStore := c.MustGet("action-store").(*action.ActionStore)
		store := c.MustGet("action").(*model.MemoryStore)
		retAction, ok := actionStore.Pop(uuid.MustParse(actionID))
		if !ok || !retAction.IsValid() {
			component := components.Empty()
			render(c, component, 400, "outerHTML", "totp-dialog")
			return
		}
		draft, ok := retAction.Draft.(model.User)
		if retAction.Type != action.UserUpdateAttempt || !ok {
			panic("not login draft")
		}
		store.UpdateUser(draft.ID, draft)
		component := view.ResourceUpdated("senha")
		render(c, component, 204, "afterbegin")
		return
	}
	var form model.PasswordChangeStruct
	err := c.ShouldBind(&form)
	if err != nil {
		var ve validator.ValidationErrors
		if errors.As(err, &ve) {
			err := make(map[string]string, 0)
			for _, fe := range ve {
				err[normalizeInputField(fe.Field())] = getErrorMsg(fe)
			}
			component := view.PassordPreference(form, err)
			render(c, component, 400, "outerHTML")
			return
		}
	}
	session := sessions.Default(c)
	store := c.MustGet("action-store").(*model.MemoryStore)
	data := getSessionData(session)
	user, _ := store.GetUser(data.UserID)
	user.HashedPassword, _ = hashPassword(form.NewPasswd)
	emailChangeAction := action.NewUserUpdateAttempt(user)
	session.Set("action", emailChangeAction.ID.String())
	component := view.TOTPDialog("/user/preferences/password")
	render(c, component, 200, "afterbegin")
}

func PreferencesGet(c *gin.Context) {
	component := view.PreferencesPage()
	render(c, component, 200)
}

func EnableMFA(c *gin.Context) {
	store := c.MustGet("action-store").(*action.ActionStore)
	session := sessions.Default(c)
	if actionID, ok := session.Get("action").(string); ok {
		retAction, ok := store.Inspect(uuid.Must(uuid.Parse(actionID)))
		if retAction.Type != action.UserUpdateAttempt {
			store.Pop(uuid.Must(uuid.Parse(actionID)))
			location(c, "/user/preferences")
			return
		}
		if ok {
			draft := retAction.Draft.(model.User)
			plaintext, _ := decryptAES(draft.EncryptedTOTPUrl)
			key, _ := otp.NewKeyFromURL(plaintext)
			component := view.TOTPConfirmationPage(key.Secret(), "", retAction.ID)
			render(c, component, 200)
			return
		}
	}
	data := getSessionData(session)
	mfaAction := action.NewMFAction()
	retAction := store.CheckDuplicate()
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

func TOTPImage(c *gin.Context) {
	store := c.MustGet("action-store").(*model.MemoryStore)
	session := sessions.Default(c)
	data := getSessionData(session)
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
