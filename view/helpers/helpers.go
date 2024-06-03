package helpers

import (
	"context"

	"github.com/alexedwards/scs/v2"
)

func GetFlash(ctx context.Context) string {
	session := ctx.Value("session").(*scs.SessionManager)
	msg := session.PopString(ctx, "flash")
	return msg
}
