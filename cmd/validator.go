package main

import (
	"github.com/go-playground/validator"
	passwordvalidator "github.com/wagslane/go-password-validator"
)

func checkPasswordEntropy(passwd string) bool {
	const minEntropyBits = 60
	entropy := passwordvalidator.GetEntropy(passwd)
	if entropy < minEntropyBits {
		return false
	}
	return true
}

var entropy validator.Func = func(fl validator.FieldLevel) bool {
	password, ok := fl.Field().Interface().(string)
	if ok {
		return checkPasswordEntropy(password)
	}
	return true
}
