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
)

type PendingTOTPConfirmation struct {
	Token            uuid.UUID
	User             model.User
	EncryptedTOTPUrl string
}

func SignUpUserGet(c *gin.Context) {
	component := view.SignUpPage(model.UserSignUp{}, map[string]string{})
	render(c, component, 200)
}

func signUpUserToUser(signup model.UserSignUp) model.User {
	return model.User{
		ID:               uuid.Must(uuid.NewRandom()),
		Name:             signup.Name,
		Email:            signup.Email,
		Role:             []model.Role{model.UserRole},
		EncryptedTOTPUrl: "",
	}
}

func SignUpUserPost(c *gin.Context) {
	var userSignUp model.UserSignUp
	err := c.ShouldBind(&userSignUp)
	if err != nil {
		var ve validator.ValidationErrors
		if errors.As(err, &ve) {
			err := make(map[string]string, len(ve))
			for _, fe := range ve {
				inputField := normalizeInputField(fe.Field())
				err[inputField] = getErrorMsg(fe)
			}
			component := view.SignUpForm(userSignUp, err)
			render(c, component, 400, "outerHTML")
		}
	}
	user := signUpUserToUser(userSignUp)
	user.HashedPassword, _ = hashPassword(userSignUp.Passwd)
	store := c.MustGet("action-store").(*action.ActionStore)
	registerAction := action.NewUserRegistration(user)
	if old, err := store.CheckDuplicate(registerAction); err != nil {
		if errors.Is(err, action.ErrExistsButExpired) {
			store.Pop(old.ID)
			component := view.ExpiredSignUp()
			render(c, component, 200)
			return
		} else if errors.Is(err, action.ErrPendingConfirmation) {
			component := view.PendingSignUp()
			render(c, component, 200)
			return
		} else {
			panic(err)
		}
	}
	store.NewAction(registerAction)
	err = sendConfirmationEmail(registerAction)
	if err != nil {
		component := view.InternalServerError("descupe tente mais tarde")
		render(c, component, 500, "afterbegin")
		return
	}
	component := view.PendingSignUp()
	render(c, component, 200)
	return
}

func ConfirmUserRegistration(c *gin.Context) {
	var ticket struct {
		Token uuid.UUID `form:"token" binding:"required, uuid"`
	}
	session := sessions.Default(c)
	if data := session.Get("session-data"); data != nil {
		location(c, "/user/home")
		return
	}
	if err := c.ShouldBind(&ticket); err != nil {
		location(c, "/signup")
	}
	store := c.MustGet("action-store").(*action.ActionStore)
	registerAction, ok := store.Pop(ticket.Token)
	if !ok {
		location(c, "/signup")
		return
	}
	user := registerAction.Draft.(model.User)
	if !registerAction.IsValid() {
		component := view.ExpiredSignUp()
		render(c, component, 200)
		return
	}
	data := model.SessionData{
		UserID: user.ID,
		Role:   user.Role,
		HasMfa: false,
	}
	setSessionData(session, data)
	session.Save()
	location(c, "/user/home")
}
