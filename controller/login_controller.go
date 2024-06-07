package controller

import (
	"errors"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/grepvenancio/biblioteca/model"
	"github.com/grepvenancio/biblioteca/view"
	"github.com/grepvenancio/biblioteca/view/components"
)

type UserLogin struct {
	Email    string `form:"email" binding:"required, email"`
	Password string `form:"passwd" binding:"required"`
}

func LoginGet(c *gin.Context) {
	component := view.LoginPage(UserLogin{}, map[string]string{})
	render(c, component, 200)
}

func LoginPost(c *gin.Context) {
	if c.GetHeader("HX-Trigger") == "totp-dialog" {
		err := verifyTOTP(c)
		if err != nil {
			component := view.TOTPInput(err.Error())
			render(c, component, 400, "outerHTML")
			return
		}
		session := sessions.Default(c)
		actionID := session.Get("action").(string)
		actionStore := c.MustGet("action-store").(*model.ActionStore)
		action, ok := actionStore.Pop(uuid.MustParse(actionID))
		if !ok || !action.IsValid() {
			component := components.Empty()
			render(c, component, 400, "outerHTML", "totp-dialog")
			return
		}
		draft, ok := action.Draft.(model.SessionData)
		if action.Type != model.LoginAttempt || !ok {
			panic("not login draft")
		}
		setSessionData(session, draft)
		session.Save()
		location(c, "/user/home")
		return
	}
	var userLogin UserLogin
	err := c.ShouldBind(&userLogin)
	if err != nil {
		var ve validator.ValidationErrors
		if errors.As(err, &ve) {
			var err map[string]string
			for _, fe := range ve {
				err[fe.Field()] = getErrorMsg(fe)
			}
			component := view.LoginForm(userLogin, err)
			render(c, component, 400, "outerHTML")
			return
		}
	}
	store := c.MustGet("store").(*model.MemoryStore)
	session := sessions.Default(c)
	user, ok := store.GetUserByEmail(userLogin.Email)
	if !ok || verifyPassword(userLogin.Password, user.HashedPassword) {
		component := view.ErrorMessageBox("Credênciais inválidas")
		render(c, component, 400, "afterbegin")
		return
	}
	hasMfa := false
	if user.EncryptedTOTPUrl != "" {
		hasMfa = true
	}
	data := model.SessionData{
		UserID: user.ID,
		Role:   user.Role,
		HasMfa: hasMfa,
	}
	if data.HasMfa {
		action := model.NewLoginAttempt(data)
		actionStore := c.MustGet("action-store").(*model.ActionStore)
		oldActionID := session.Get("action").(string)
		actionStore.Pop(uuid.MustParse(oldActionID))
		actionStore.NewAction(action)
		session.Set("action", action.ID.String())
		component := view.TOTPDialog("/login", "")
		render(c, component, 200)
	}
	_ = setSessionData(session, data)
	session.Save()
	location(c, "/user/home")
}
