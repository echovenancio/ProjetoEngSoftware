package model

import "github.com/google/uuid"

type BookStore interface {
	InsertBook(book Book)
	DeleteBook(isbn string) error
	UpdateBook(isbn string, updatedBook Book) error
	GetBook(isbn string) (*Book, bool)
	BooksCount() int
	QueryBooks(param string, page int) ([]Book, bool)
	GetAllBooks(page int) ([]Book, bool)
}

type LeaseStore interface {
	InsertLease(lease Lease)
	DeleteLease(id uuid.UUID) error
	UpdateLease(id uuid.UUID, updatedLease Lease) error
	GetLease(id uuid.UUID) (bool, *Lease)
	GetAllLease() []Lease
}

type UserStore interface {
	InsertUser(user User)
	DeleteUser(id uuid.UUID) error
	GetUser(id uuid.UUID) (bool, *User)
	GetUserByEmail(email string) (bool, *User)
	UpdateUser(id uuid.UUID, uptadedUser User) error
	GetAllUsers() []User
}

type PendingTOTPConfirmationStore interface {
	EnableTOTP(totpConfirmationObject PendingTOTPConfirmation) error
	GetPendingTOTPObject(ticketID uuid.UUID) (PendingTOTPConfirmation, bool)
	ConfirmTOTP(ticketID uuid.UUID) error
	CancelTOTPTicket(ticketID uuid.UUID) error
	GetTOTPTicketPerUserId(userID uuid.UUID) (PendingTOTPConfirmation, bool)
}

type PendingUserStore interface {
	NewPendingUserRegistration(pendingUser PendingUser) error
	UpdateConfirmationToken(email string, newToken uuid.UUID) (PendingUser, error)
	ConfirmUserRegistration(token uuid.UUID) (User, error)
}

type PendingEmailChangeStore interface {
	NewPendingEmailChange(ticket PendindEmailChange)
	ConfirmEmailChange(ticketID uuid.UUID) (bool, PendindEmailChange)
}

type RecoveryPasswordStore interface {
	NewPasswordRecoveryTicket(ticket PasswordRecoverTicket)
	TicketStatus(ticket uuid.UUID) (string, error)
	ResetPassword(ticket uuid.UUID, pin string, newPassword string) error
	GenerateNewPin(ticket uuid.UUID, pin string) (PasswordRecoverTicket, error)
	VerifyPin(ticket uuid.UUID, pin string) (bool, error)
	UpgradeStatus(ticket uuid.UUID) (PasswordRecoverTicket, error)
}

type Store interface {
	UserStore
	BookStore
	LeaseStore
	PendingUserStore
	RecoveryPasswordStore
	PendingTOTPConfirmation
	PendingEmailChangeStore
}
