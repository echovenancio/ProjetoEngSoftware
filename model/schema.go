package model

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Role string

const (
	AdminRole Role = "admin"
	UserRole  Role = "user"
)

type JwtConfirmationTokenClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

var (
	RecoverAwaitingPin = "await pin code"
	RecoverResetPasswd = "reseting password"
)

type UserSignUp struct {
	Name               string `form:"name" binding:"required"`
	Email              string `form:"email" binding:"required, email"`
	Passwd             string `form:"passwd" binding:"required, entropy"`
	PasswdConfirmation string `form:"passwd-confirmation" binding:"required, eqfield=passwd"`
}

type PasswordChangeStruct struct {
	Passwd             string `form:"passwd" binding:"required"`
	NewPasswd          string `form:"passwd" binding:"required, entropy, nefield=passwd"`
	PasswdConfirmation string `form:"passwd-confirmation" binding:"required, eqfield=new-passwd"`
}

type PasswordRecoverTicket struct {
	Ticket uuid.UUID
	User   User
	Pin    string
	Status string
	Exp    time.Time
}

type Book struct {
	Title     string `form:"title" binding:"required"`
	Isbn13    string `form:"isbn-13" binding:"required, isbn13"`
	Isbn10    string `form:"isbn-10" binding:"required, isbn10"`
	Pages     int    `form:"pages" binding:"required"`
	Author    string `form:"author" binding:"required"`
	Genre     string `form:"genre" binding:"required"`
	Publisher string `form:"publisher" binding:"required"`
	Edition   string `form:"edition" binding:"required"`
}

type User struct {
	ID               uuid.UUID
	Name             string
	Email            string
	HashedPassword   string
	Role             []Role
	EncryptedTOTPUrl string
}

type PendindEmailChange struct {
	TicketID uuid.UUID
	UserID   uuid.UUID
	OldEmail string
	NewEmail string
}

type PasswordRecoverUser struct {
	Ticket               uuid.UUID
	Password             string
	ConfitmationPassword string
}

type SessionData struct {
	UserID uuid.UUID `json:"uid"`
	Role   []Role    `json:"role"`
	HasMfa bool      `json:"has_mfa"`
}

type MFAReason string

var (
	ReasonLogin         MFAReason = "login"
	ReasenSensitivePref MFAReason = "preference"
)

type MFARequest struct {
	ID       uuid.UUID
	Redirect string
	Reason   MFAReason
}

type PendingUser struct {
	User              User
	ConfirmationToken uuid.UUID
	Exp               time.Time
}

type Lease struct {
	ID             uuid.UUID
	Book           Book
	Client         User
	ExpirationDate time.Time
	ReturnDate     time.Time
	IsActive       bool
}
