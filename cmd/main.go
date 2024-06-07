package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator"
	"github.com/grepvenancio/biblioteca/controller"
	"github.com/grepvenancio/biblioteca/model"
	"github.com/joho/godotenv"
)

var store *model.MemoryStore
var actionStore *model.ActionStore

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		panic("Error loading .env")
	}
	sessionStore := memstore.NewStore([]byte("secret"))
	store = model.NewMemoryStore()
	actionStore = model.NewActionStore()
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		v.RegisterValidation("entropy", entropy)
	}
	r := gin.Default()
	r.Use(sessions.Sessions("session", sessionStore))
	r.Use(func(c *gin.Context) {
		c.Set("store", store)
		c.Set("action-store", actionStore)
		c.Next()
	})
	r.Use(CSPolicy)
	r.Static("/static", "static")

	adminGroup := r.Group("/admin").Use(UserAuth).Use(AdminAuth)
	{
		adminGroup.GET("/books", controller.GetAllBooks)
		adminGroup.GET("/books/:isbn", controller.GetBook)
		adminGroup.DELETE("/books/:isbn", controller.DeleteBook)
		adminGroup.GET("/books:isbn/edit", controller.UpdateBookGet)
		adminGroup.PUT("/books:isbn/edit", controller.UpdateBookPut)
		adminGroup.PUT("/books/get_by", controller.BookIsbnGet)
		adminGroup.PUT("/books/count", controller.BooksCountGet)
	}

	r.Group("/", func(r chi.Router) {
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
	_ = r.Run(":8080")
}

func Wrapper(h http.Handler) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		h.ServeHTTP(ctx.Writer, ctx.Request)
	}
}

func CSPolicy(c *gin.Context) {
	rngbuf := make([]byte, 16)
	rand.Read(rngbuf)
	nonce := base64.StdEncoding.EncodeToString(rngbuf)
	csp := fmt.Sprintf(`script-src 'nonce-%s' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`, nonce)
	c.Header("Content-Security-Policy", csp)
	c.Set("nonce", nonce)
	c.Next()
}

func UserAuth(c *gin.Context) {
	session := sessions.Default(c)
	jsonData := session.Get("session-data")
	if jsonData == nil {
		c.Header("HX-Location", "/login")
		return
	}
	var sessionData model.SessionData
	_ = json.Unmarshal(jsonData.([]byte), &sessionData)
	c.Set("session-struct", sessionData)
	c.Next()
}

func AdminAuth(c *gin.Context) {
	isAdmin := false
	sessionData := c.MustGet("session-struct").(model.SessionData)
	for _, role := range sessionData.Role {
		if role == model.AdminRole {
			isAdmin = true
		}
	}
	if !isAdmin {
		c.Header("HX-Location", "/login")
		return
	}
	c.Next()
}
