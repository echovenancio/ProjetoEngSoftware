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

type PasswordRecoverTicket struct {
	Ticket uuid.UUID
	User   User
	Pin    string
	Status string
	Exp    time.Time
}

type Book struct {
	Title     string
	Isbn      string
	Pages     int
	Author    string
	Genre     string
	Publisher string
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

type UserSignUp struct {
	Name     string
	Email    string
	Password string
}

type PendingTOTPConfirmation struct {
	Token            uuid.UUID
	User             User
	EncryptedTOTPUrl string
}

type PasswordRecoverUser struct {
	Ticket               uuid.UUID
	Password             string
	ConfitmationPassword string
}

type UserLogin struct {
	Email    string
	Password string
}

type SessionData struct {
	ID         uuid.UUID
	Role       []Role
	HasMfa     bool
	PendingMFA bool
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
