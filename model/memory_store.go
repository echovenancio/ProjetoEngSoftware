package model

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	uerrors "github.com/grepvenancio/biblioteca/errors"
)

type MemoryStore struct {
	books              []Book
	lease              []Lease
	users              []User
	pendingUsers       []PendingUser
	passwordRecover    []PasswordRecoverTicket
	pendingTOTP        []PendingTOTPConfirmation
	pendingEmailChange []PendindEmailChange
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		books:              make([]Book, 0),
		lease:              make([]Lease, 0),
		users:              make([]User, 0),
		pendingUsers:       make([]PendingUser, 0),
		passwordRecover:    make([]PasswordRecoverTicket, 0),
		pendingTOTP:        make([]PendingTOTPConfirmation, 0),
		pendingEmailChange: make([]PendindEmailChange, 0),
	}
}

func (s *MemoryStore) BooksCount() int {
	return len(s.books)
}

func (s *MemoryStore) InsertBook(book Book) {
	s.books = append(s.books, book)
}

func (s *MemoryStore) QueryBooks(param string, page int) ([]Book, bool) {
	books := make([]Book, 0)
	retBooks, hasMoreBooks := s.GetAllBooks(page)
	for _, book := range retBooks {
		if strings.Contains(book.Title, param) ||
			strings.Contains(book.Isbn, param) ||
			strings.Contains(book.Genre, param) ||
			strings.Contains(book.Author, param) ||
			strings.Contains(book.Publisher, param) {
			books = append(books, book)
		}
	}
	return books, hasMoreBooks
}

func (s *MemoryStore) DeleteBook(isbn string) error {
	storeLen := len(s.lease)
	for i, book := range s.books {
		if book.Isbn == isbn {
			s.books = s.books[:i:storeLen]
			return nil
		}
	}
	return errors.New("Cannot find isbn in store.")
}

func (s *MemoryStore) GetBook(isbn string) (*Book, bool) {
	for _, book := range s.books {
		if book.Isbn == isbn {
			return &book, true
		}
	}
	return nil, false
}

func (s *MemoryStore) UpdateBook(isbn string, updatedBook Book) error {
	for i, book := range s.books {
		if book.Isbn == isbn {
			s.books[i] = updatedBook
			return nil
		}
	}
	return errors.New("Cannot find isbn in store.")
}

func (s *MemoryStore) GetAllBooks(page int) ([]Book, bool) {
	hasMorebooks := true
	booksLen := len(s.books)
	upperBound := page * 3
	lowerBound := upperBound - 3
	if upperBound >= booksLen {
		hasMorebooks = false
		upperBound = booksLen
	}
	if lowerBound >= booksLen {
		lowerBound = 0
	}
	return s.books[lowerBound:upperBound], hasMorebooks
}

func (s *MemoryStore) InsertLease(lease Lease) {
	s.lease = append(s.lease, lease)
}

func (s *MemoryStore) DeleteLease(id uuid.UUID) error {
	storeLen := len(s.lease)
	for i, lease := range s.lease {
		if lease.ID == id {
			s.lease = s.lease[: i : storeLen-1]
			return nil
		}
	}
	return errors.New("Cannot find isbn in store.")
}

func (s *MemoryStore) UpdateLease(id uuid.UUID, updatedLease Lease) error {
	for i, lease := range s.lease {
		if lease.ID == id {
			s.lease[i] = updatedLease
			return nil
		}
	}
	return errors.New("id not found in store")
}

func (s *MemoryStore) GetLease(id uuid.UUID) (bool, *Lease) {
	for _, lease := range s.lease {
		if lease.ID == id {
			return true, &lease
		}
	}
	return false, nil
}

func (s *MemoryStore) GetAllLease() []Lease {
	return s.lease
}

func (s *MemoryStore) InsertUser(user User) {
	s.users = append(s.users, user)
}

func (s *MemoryStore) DeleteUser(id uuid.UUID) error {
	storeLen := len(s.users)
	for i, user := range s.users {
		if user.ID == id {
			s.users = s.users[: i : storeLen-1]
			return nil
		}
	}
	return errors.New("Cannot find user in store.")
}

func (s *MemoryStore) GetUser(id uuid.UUID) (User, bool) {
	for _, user := range s.users {
		if user.ID == id {
			return user, true
		}
	}
	return User{}, false
}

func (s *MemoryStore) GetUserByEmail(email string) (User, bool) {
	for _, user := range s.users {
		if user.Email == email {
			return user, true
		}
	}
	return User{}, false
}

func (s *MemoryStore) UpdateUser(id uuid.UUID, uptadedUser User) error {
	for i, user := range s.users {
		if user.ID == id {
			s.users[i] = uptadedUser
			return nil
		}
	}
	return errors.New("id not found in store")
}

func (s *MemoryStore) GetAllUsers() []User {
	return s.users
}

func (s *MemoryStore) NewPendingUserRegistration(newPendingUser PendingUser) error {
	for _, pendingUser := range s.pendingUsers {
		if pendingUser.User.Email == newPendingUser.User.Email {
			fmt.Println("oxi")
			return fmt.Errorf("Email already in pending list")
		}
	}
	s.pendingUsers = append(s.pendingUsers, newPendingUser)
	return nil
}

func (s *MemoryStore) ConfirmUserRegistration(token uuid.UUID) (User, error) {
	listLen := len(s.pendingUsers)
	fmt.Println("Users pendentes -------------")
	fmt.Println(s.pendingUsers)
	fmt.Println("-----------------------------")
	for i, pendingUser := range s.pendingUsers {
		fmt.Println(pendingUser.ConfirmationToken)
		fmt.Println(token)
		if pendingUser.ConfirmationToken == token {
			if pendingUser.Exp.Before(time.Now()) {
				return pendingUser.User, uerrors.ErrExpiredConfToken
			}
			fmt.Println("achei")
			s.InsertUser(pendingUser.User)
			s.pendingUsers = s.pendingUsers[: i : listLen-1]
			return pendingUser.User, nil
		}
	}
	return User{}, uerrors.ErrConfTokenNotFound
}

func (s *MemoryStore) UpdateConfirmationToken(
	email string, newToken uuid.UUID) (PendingUser, error) {
	for i, pendingUser := range s.pendingUsers {
		if pendingUser.User.Email == email {
			fmt.Printf("---------------------\nAchei o update %s, old=%s, new=%s", pendingUser.User.Name, pendingUser.ConfirmationToken, newToken)
			pendingUser.ConfirmationToken = newToken
			s.pendingUsers[i] = pendingUser
			return pendingUser, nil
		}
	}
	return PendingUser{}, fmt.Errorf("no pending user with email=%v", email)
}

func (s *MemoryStore) NewPasswordRecoveryTicket(
	ticket PasswordRecoverTicket) {
	s.passwordRecover = append(s.passwordRecover, ticket)
}

func (s *MemoryStore) ResetPassword(
	ticket uuid.UUID, pin string, newPassword string) error {
	listLen := len(s.passwordRecover)
	for i, psUser := range s.passwordRecover {
		if psUser.Ticket == ticket && psUser.Pin == pin {
			if psUser.Exp.Before(time.Now()) {
				return uerrors.ErrTicketExpired
			}
			psUser.User.HashedPassword = newPassword
			s.UpdateUser(psUser.User.ID, psUser.User)
			s.passwordRecover = s.passwordRecover[: i : listLen-1]
			return nil
		} else if psUser.Ticket == ticket {
			return uerrors.ErrInvalidPin
		}
	}
	return uerrors.ErrPinNotFound
}

func (s *MemoryStore) TicketStatus(ticket uuid.UUID) (string, error) {
	for _, t := range s.passwordRecover {
		if t.Ticket == ticket {
			return t.Status, nil
		}
	}
	return "", uerrors.ErrTicketNotFound
}

func (s *MemoryStore) GenerateNewPin(
	ticket uuid.UUID, pin string) (PasswordRecoverTicket, error) {
	for i, t := range s.passwordRecover {
		if t.Ticket == ticket {
			t.Pin = pin
			t.Exp = time.Now().Add(2 * time.Minute)
			t.Status = RecoverAwaitingPin
			s.passwordRecover[i] = t
			return t, nil
		}
	}
	return PasswordRecoverTicket{}, uerrors.ErrTicketNotFound
}

func (s *MemoryStore) VerifyPin(ticket uuid.UUID, pin string) (bool, error) {
	for _, t := range s.passwordRecover {
		if t.Ticket == ticket {
			if t.Exp.Before(time.Now()) {
				return false, uerrors.ErrTicketExpired
			}
			if t.Pin != pin {
				return false, uerrors.ErrInvalidPin
			}
			return true, nil
		}
	}
	return false, uerrors.ErrTicketNotFound
}

func (s *MemoryStore) UpgradeStatus(ticket uuid.UUID) (PasswordRecoverTicket, error) {
	for i, t := range s.passwordRecover {
		if t.Ticket == ticket {
			t.Status = RecoverResetPasswd
			s.passwordRecover[i] = t
			return t, nil
		}
	}
	return PasswordRecoverTicket{}, uerrors.ErrTicketNotFound
}

func (s *MemoryStore) EnableTOTP(
	totpConfirmationObject PendingTOTPConfirmation) error {
	for _, t := range s.pendingTOTP {
		if t.User.ID == totpConfirmationObject.User.ID {
			return fmt.Errorf("user alredy pendind totp confirmation")
		}
	}
	s.pendingTOTP = append(s.pendingTOTP, totpConfirmationObject)
	return nil
}

func (s *MemoryStore) ConfirmTOTP(ticketID uuid.UUID) error {
	listLen := len(s.pendingTOTP)
	for i, t := range s.pendingTOTP {
		if t.Token == ticketID {
			t.User.EncryptedTOTPUrl = t.EncryptedTOTPUrl
			s.UpdateUser(t.User.ID, t.User)
			s.pendingTOTP = s.pendingTOTP[:i:listLen]
			return nil
		}
	}
	return fmt.Errorf("no ticket in pending list")
}
func (s *MemoryStore) CancelTOTPTicket(ticketID uuid.UUID) error {
	listLen := len(s.pendingTOTP)
	for i, t := range s.pendingTOTP {
		if t.Token == ticketID {
			s.pendingTOTP = s.pendingTOTP[:i:listLen]
			return nil
		}
	}
	return fmt.Errorf("no ticket in pending list")
}

func (s *MemoryStore) GetTOTPTicketPerUserId(userID uuid.UUID) (PendingTOTPConfirmation, bool) {
	for _, t := range s.pendingTOTP {
		if t.User.ID == userID {
			return t, true
		}
	}
	return PendingTOTPConfirmation{}, false
}

func (s *MemoryStore) GetPendingTOTPObject(ticketID uuid.UUID) (PendingTOTPConfirmation, bool) {
	for _, t := range s.pendingTOTP {
		if t.Token == ticketID {
			return t, true
		}
	}
	return PendingTOTPConfirmation{}, false
}

func (s *MemoryStore) NewPendingEmailChange(ticket PendindEmailChange) {
	for i, t := range s.pendingEmailChange {
		if t.UserID == ticket.UserID {
			s.pendingEmailChange[i] = ticket
		}
	}
	s.pendingEmailChange = append(s.pendingEmailChange, ticket)
}
func (s *MemoryStore) ConfirmEmailChange(
	ticketID uuid.UUID) (bool, PendindEmailChange) {
	listLen := len(s.pendingEmailChange)
	for i, t := range s.pendingEmailChange {
		if t.TicketID == ticketID {
			ok, user := s.GetUserByEmail(t.OldEmail)
			if !ok {
				return false, PendindEmailChange{}
			}
			user.Email = t.NewEmail
			_ = s.UpdateUser(user.ID, *user)
			s.pendingEmailChange = s.pendingEmailChange[:i:listLen]
			return true, t
		}
	}
	return false, PendindEmailChange{}
}
