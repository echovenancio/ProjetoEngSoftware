package action

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/grepvenancio/biblioteca/model"
)

type ActionIntent string

const (
	LoginAttempt      ActionIntent = "login"
	UserRegistration  ActionIntent = "signup"
	UserUpdateAttempt ActionIntent = "update"
)

type ActionError string

func (a ActionError) Error() string {
	return fmt.Sprint(a)
}

const (
	ErrExistsButExpired    ActionError = "ticket exists, but expired"
	ErrPendingConfirmation ActionError = "user already pending confirmation"
	ErrNotRegisted         ActionError = "action not registered"
)

type Action struct {
	ID    uuid.UUID
	Type  ActionIntent
	Draft any
	Exp   time.Time
}

func NewLoginAttempt(draft any) Action {
	return Action{
		ID:    uuid.Must(uuid.NewRandom()),
		Type:  LoginAttempt,
		Draft: draft,
		Exp:   time.Now().Add(5 * time.Minute),
	}
}

func NewUserUpdateAttempt(draft any) Action {
	return Action{
		ID:    uuid.Must(uuid.NewRandom()),
		Type:  UserUpdateAttempt,
		Draft: draft,
		Exp:   time.Now().Add(2 * time.Hour),
	}
}

func NewUserRegistration(draft any) Action {
	return Action{
		ID:    uuid.Must(uuid.NewRandom()),
		Type:  UserRegistration,
		Draft: draft,
		Exp:   time.Now().Add(2 * time.Hour),
	}
}

func (a *Action) IsValid() bool {
	return a.Exp.After(time.Now())
}

type ActionStore struct {
	store []Action
}

func NewActionStore() *ActionStore {
	return &ActionStore{store: make([]Action, 0)}
}

func (s *ActionStore) NewAction(action Action) {
	s.store = append(s.store, action)
}

func (s *ActionStore) Inspect(actionID uuid.UUID) (Action, bool) {
	for _, a := range s.store {
		if a.ID == actionID {
			return a, true
		}
	}
	return Action{}, false
}

func (s *ActionStore) Pop(actionID uuid.UUID) (Action, bool) {
	listLen := len(s.store)
	for i, a := range s.store {
		if a.ID == actionID {
			s.store = s.store[:i:listLen]
			return a, true
		}
	}
	return Action{}, false
}

func (s *ActionStore) MustPop(actionID uuid.UUID) Action {
	ret, ok := s.Pop(actionID)
	if !ok {
		panic("actionID not found in store")
	}
	return ret
}

func (s *ActionStore) CheckDuplicate(action Action) (Action, error) {
	switch action.Type {
	case UserRegistration:
		if a, ok := handleSignUp(action.Draft.(model.UserSignUp), s); !ok {
			if !a.IsValid() {
				return a, ErrExistsButExpired
			}
			return a, ErrPendingConfirmation
		}
	case UserUpdateAttempt:
		if a, ok := handleUserUpdade(action.Draft.(model.User), s); !ok {
			if !a.IsValid() {
				return a, ErrExistsButExpired
			}
			return a, ErrPendingConfirmation
		}
	default:
		return Action{}, ErrNotRegisted
	}
	return Action{}, nil
}

func handleSignUp(user model.UserSignUp, s *ActionStore) (Action, bool) {
	for _, a := range s.store {
		if reg, ok := a.Draft.(model.UserSignUp); ok &&
			user.Email == reg.Email {
			return a, false
		}
	}
	return Action{}, true
}

func handleUserUpdade(user model.User, s *ActionStore) (Action, bool) {
	for _, a := range s.store {
		if reg, ok := a.Draft.(model.User); ok &&
			user.ID == reg.ID {
			return a, false
		}
	}
	return Action{}, true
}
