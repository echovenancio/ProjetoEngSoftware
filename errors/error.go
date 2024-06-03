package errors

import (
	"errors"
	"fmt"
	"strings"
)

type FormError map[string]string

var (
	ErrTicketExpired     = errors.New("ticket in expired")
	ErrPinNotFound       = errors.New("pin not found")
	ErrInvalidPin        = errors.New("invalid pin")
	ErrTicketNotFound    = errors.New("ticket not found")
	ErrExpiredConfToken  = errors.New("confirmation token is expired")
	ErrConfTokenNotFound = errors.New("confirmation token not found")
)

func (formError FormError) Error() string {
	var msg strings.Builder
	for key, value := range formError {
		msg.WriteString(fmt.Sprintf("%s: %s ", key, value))
	}
	return msg.String()
}
