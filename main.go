package main

import (
	"fmt"
	"net/http"

	"github.com/chmike/securecookie"

	"github.com/rs/zerolog/log"
)

type helloHandler struct {
}

func (h *helloHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess := SessionGet(r.Context())

	if !sess.IsValid() {
		if user, pwd, ok := r.BasicAuth(); ok {
			if user == "test" && pwd == "1234" {
				sess.updated(42)
			} else {
				log.Error().Msgf("bad user (%s) and password (%s)", user, pwd)
				w.Header().Set("WWW-Authenticate", "Basic")
				w.WriteHeader(401)
				return
			}
		} else {
			w.Header().Set("WWW-Authenticate", "Basic")
			w.WriteHeader(401)
			return
		}
	}

	fmt.Fprintf(w, "hello with secure cookie!")
}

func main() {
	hello := helloHandler{}
	key := securecookie.MustGenerateRandomKey()
	mw := Middleware("localhost", "/", &log.Logger, key)

	http.Handle("/", mw(&hello))

	log.Info().Msg("server starting up")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Error().Err(err).Msg("server startup error")
	}
}
