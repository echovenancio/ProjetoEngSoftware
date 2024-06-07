package controller

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
	session.Put(r.Context(), "flash", "email atualizado com sucesso") view.PreferencesPage().Render(r.Context(), w)
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
