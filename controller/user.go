package controller

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/google/uuid"
	"github.com/grepvenancio/biblioteca/model"
	"github.com/grepvenancio/biblioteca/utils"
	"github.com/grepvenancio/biblioteca/view"
)

func UserHomePage(w http.ResponseWriter, r *http.Request) {
	component := view.UserHomePage()
	component.Render(r.Context(), w)
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
