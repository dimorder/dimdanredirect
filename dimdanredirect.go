package dimdanredirect

import (
	"context"
	"gitlab.com/rwxrob/uniq"
	"net/http"
)

// Config holds configuration to be passed to the plugin
type Config struct {
}

// CreateConfig populates the Config data object
func CreateConfig() *Config {
	return &Config{}
}

// DimdanRedirect holds the necessary components of a Traefik plugin
type DimdanRedirect struct {
	next http.Handler
	name string
}

// New instantiates and returns the required components used to handle a HTTP request
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &DimdanRedirect{
		next: next,
		name: name,
	}, nil
}

func (d *DimdanRedirect) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	uid := uniq.UUID()
	rw.Write([]byte(uid))
}
