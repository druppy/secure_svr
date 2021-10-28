package main

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/chmike/securecookie"
	"github.com/rs/zerolog"
)

const sessionRefreshTresshold = 60 * 10 // number of seconds old before setting new cookie
const sessionMaxAge = 60 * 60 * 1

type contextKey string

const session_key contextKey = "__session"

type Session struct {
	UserID  int64 // valid user id
	valid   bool
	updated func(int64) // lambda called when UserId is updated
}

func (sess *Session) UserIDSet(id int64) {
	sess.UserID = id
	sess.valid = true
	if sess.updated != nil {
		sess.updated(sess.UserID)
	}
}

func (sess *Session) IsValid() bool {
	return sess.valid
}

func (sess *Session) Allow(permissionName string) bool {
	return sess.valid
}

// if a context have a session we will find and return it, this have been send by the middle ware
func SessionGet(ctx context.Context) *Session {
	key := ctx.Value(session_key)

	if key != nil {
		if sess, ok := key.(*Session); ok {
			return sess
		}
	}

	return nil
}

func Middleware(siteName string, path string, l *zerolog.Logger, sessionKey []byte) func(next http.Handler) http.Handler {
	obj, err := securecookie.New("session", sessionKey, securecookie.Params{
		Path:     path,                // cookie received only when URL starts with this path
		Domain:   siteName,            // cookie received only when URL domain matches this one
		MaxAge:   sessionMaxAge,       // cookie becomes invalid sessionMaxAge seconds after it is set
		HTTPOnly: true,                // disallow access by remote javascript code
		Secure:   true,                // cookie received only with HTTPS, never with HTTP
		SameSite: securecookie.Strict, // cookie received with same or sub-domain names
	})

	if err != nil {
		l.Fatal().Err(err).Msg("session middleware init error")
	}

	setCookie := func(w http.ResponseWriter, userID int64) {
		idStr := strconv.FormatInt(userID, 10)
		if err := obj.SetValue(w, []byte(idStr)); err != nil {
			l.Error().Err(err).Msg("can not set cookie on response")
		} else {
			l.Info().Msgf("set cookie for user id %d", userID)
		}
	}

	getCookie := func(w http.ResponseWriter, r *http.Request) (*Session, time.Time, error) {
		result, stamp, err := obj.GetValueAndStamp(nil, r)
		if err != nil {
			l.Info().Msg("preparing a invalid cookie")
			return &Session{
				valid: false,
				updated: func(userID int64) {
					setCookie(w, userID)
				},
			}, time.Time{}, err
		}

		id, err := strconv.ParseInt(string(result), 10, 64)
		if err != nil {
			l.Error().Err(err).Msg("cookie string is not an ID (int) value")
			return nil, time.Time{}, err
		}

		l.Info().Msgf("found a valid cookie for user %d", id)
		return &Session{
			UserID: id,
			valid:  true,
			updated: func(userID int64) {
				setCookie(w, userID)
			},
		}, stamp, nil
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, stamp, err := getCookie(w, r)
			if err != nil {
				stamp = time.Now()
			}

			ctx := context.WithValue(r.Context(), session_key, sess)

			// refresh session if close to its life span, but not all the time
			if sess.valid {
				age := time.Now().Unix() - stamp.Unix()

				if age > sessionRefreshTresshold {
					sess.updated(sess.UserID) // only set new session when below refresh treshhold
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
