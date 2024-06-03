package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/grepvenancio/biblioteca/controller"
	"github.com/grepvenancio/biblioteca/model"
	"github.com/joho/godotenv"
)

var store *model.MemoryStore
var sessionManager *scs.SessionManager

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		panic("Error loading .env")
	}
	store = model.NewMemoryStore()
	sessionManager = scs.New()
	sessionManager.Lifetime = 24 * time.Hour
	r := chi.NewRouter()
	fs := http.FileServer(http.Dir("static"))
	r.Use(middleware.Logger)
	r.Use(sessionManager.LoadAndSave)
	r.Use(storeContext)
	r.Use(sessionContext)
	r.Use(CSPolicy)
	r.Handle("/static/*", http.StripPrefix("/static/", fs))
	r.Route("/", func(r chi.Router) {
		r.Get("/", controller.Home)
		r.With(UserAuth).With(AdminAuth).Route("/admin", func(r chi.Router) {
			r.Route("/books", func(r chi.Router) {
				r.Get("/", controller.GetAllBooks)
				r.Get("/{bookIsbn}", controller.GetBook)
				r.Delete("/{bookIsbn}", controller.DeleteBook)
				r.Get("/{bookIsbn}/edit", controller.UpdateBookGet)
				r.Put("/{bookIsbn}/edit", controller.UpdateBookPut)
				r.Get("/get_by", controller.BookIsbnGet)
				r.Get("/count", controller.BooksCountGet)
			})
			r.Route("/books/new", func(r chi.Router) {
				r.Get("/", controller.InsertBookGet)
				r.Post("/", controller.InsertBookPost)
			})
		})
		r.Get("/signup", controller.SignUpUserGet)
		r.Post("/signup", controller.SignUpUserPost)
		r.Get("/signup/confirm", controller.ConfirmUserRegistration)
		r.Post("/signup/retry", controller.SignUpRetry)
		r.Get("/login", controller.LoginGet)
		r.Post("/login", controller.LoginPost)
		r.Get("/login/recover", controller.RecoverPasswordGet)
		r.Post("/login/recover", controller.RecoverPasswordPost)
		r.Get("/login/recover/retry", controller.RetryPasswordRecover)
		r.With(UserAuth).Route("/user", func(r chi.Router) {
			r.Get("/home", controller.UserHomePage)
			r.Get("/preferences", controller.PreferencesGet)
			r.Put("/preferences/name", controller.ChangeName)
			r.Put("/preferences/email", controller.ChangeEmail)
			r.Get("/preferences/email/confirm",
				controller.ConfirmEmailChange)
			r.Put("/preferences/passwd", controller.ChangePassword)
			r.Put("/preferences/totp", controller.EnableMFA)
			r.Post("/preferences/totp/verify", controller.VerifyMFA)
			r.Put("/preferences/totp/confirm/{token}", controller.ConfirmTOTP)
			r.Get("/preferences/totp/image/{token}", controller.TOTPImage)
			r.Delete("/preferences/totp/{token}", controller.CancelTOTP)
		})
	})
	http.ListenAndServe(":8080", r)
}

func storeContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), "store", store)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func sessionContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), "session", sessionManager)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func CSPolicy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rngbuf := make([]byte, 16)
		rand.Read(rngbuf)
		nonce := base64.StdEncoding.EncodeToString(rngbuf)
		csp := fmt.Sprintf(`script-src 'nonce-%s' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`, nonce)
		w.Header().Set("Content-Security-Policy", csp)
		ctx := context.WithValue(r.Context(), "nonce", nonce)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func UserAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := r.Context().Value("session").(*scs.SessionManager)
		sessionData := session.Get(r.Context(), "session-data")
		if sessionData == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		sessionDataBytes, _ := sessionData.([]byte)
		var sessionDataStruct model.SessionData
		buffer := bytes.NewBuffer(sessionDataBytes)
		_ = gob.NewDecoder(buffer).Decode(&sessionDataStruct)
		ctx := context.WithValue(
			r.Context(), "session-struct", sessionDataStruct)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func AdminAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isAdmin := false
		roles := r.Context().Value("roles").([]model.Role)
		for _, role := range roles {
			if role == model.AdminRole {
				isAdmin = true
			}
		}
		if !isAdmin {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}
