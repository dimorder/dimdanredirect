package dimdanredirect

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
)

// Config holds configuration to be passed to the plugin
type Config struct {
	DimdanDomain         string
	TakeawayDomain       string
	ShopDomain           string
	SDeliveryDomain      string
	StoreDirectoryDomain string
}

// CreateConfig populates the Config data object
func CreateConfig() *Config {
	return &Config{}
}

// DimdanRedirect holds the necessary components of a Traefik plugin
type DimdanRedirect struct {
	next                 http.Handler
	name                 string
	dimdanDomain         string
	takeawayDomain       string
	shopDomain           string
	sDeliveryDomain      string
	storeDirectoryDomain string
}

// New instantiates and returns the required components used to handle a HTTP request
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.DimdanDomain == "" {
		return nil, fmt.Errorf("DimdanDomain cannot be empty")
	}
	if config.TakeawayDomain == "" {
		return nil, fmt.Errorf("TakeawayDomain cannot be empty")
	}
	if config.ShopDomain == "" {
		return nil, fmt.Errorf("ShopDomain cannot be empty")
	}
	if config.SDeliveryDomain == "" {
		return nil, fmt.Errorf("SDeliveryDomain cannot be empty")
	}
	if config.StoreDirectoryDomain == "" {
		return nil, fmt.Errorf("StoreDirectoryDomain cannot be empty")
	}
	return &DimdanRedirect{
		next:                 next,
		name:                 name,
		dimdanDomain:         config.DimdanDomain,
		takeawayDomain:       config.TakeawayDomain,
		shopDomain:           config.ShopDomain,
		sDeliveryDomain:      config.SDeliveryDomain,
		storeDirectoryDomain: config.StoreDirectoryDomain,
	}, nil
}

func (d *DimdanRedirect) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	queryValues := req.URL.Query()

	// dimdan
	t, okT := queryValues["t"]
	m, okM := queryValues["m"]
	if okT && len(t) > 0 && okM && len(m) > 0 && d.dimdanDomain != req.Host {
		u := url.URL{Scheme: "http", Host: d.dimdanDomain, Path: req.URL.Path, RawQuery: req.URL.RawQuery}
		log.Printf("m: %+v, t: %+v, redirect to %s", m, t, u.String())
		http.Redirect(rw, req, u.String(), http.StatusSeeOther)
		return
	}

	// takeaway
	takeaway, ok := queryValues["takeaway"]
	if ok && takeaway[0] == "true" && d.takeawayDomain != req.Host {
		u := url.URL{Scheme: "http", Host: d.takeawayDomain, Path: req.URL.Path, RawQuery: req.URL.RawQuery}
		log.Printf("takeaway: %+v, redirect to %s", takeaway, u.String())
		http.Redirect(rw, req, u.String(), http.StatusSeeOther)
		return
	}

	// shop
	shop, ok := queryValues["shop"]
	if ok && shop[0] == "true" && d.shopDomain != req.Host {
		u := url.URL{Scheme: "http", Host: d.shopDomain, Path: req.URL.Path, RawQuery: req.URL.RawQuery}
		log.Printf("shop: %+v, redirect to %s", shop, u.String())
		http.Redirect(rw, req, u.String(), http.StatusSeeOther)
		return
	}

	// sdelivery
	sdelivery, ok := queryValues["sdelivery"]
	if ok && takeaway[0] == "true" && d.sDeliveryDomain != req.Host {
		u := url.URL{Scheme: "http", Host: d.sDeliveryDomain, Path: req.URL.Path, RawQuery: req.URL.RawQuery}
		log.Printf("sdelivery: %+v, redirect to %s", sdelivery, u.String())
		http.Redirect(rw, req, u.String(), http.StatusSeeOther)
		return
	}

	// dir
	dir, ok := queryValues["dir"]
	if ok && dir[0] == "true" && d.storeDirectoryDomain != req.Host {
		u := url.URL{Scheme: "http", Host: d.storeDirectoryDomain, Path: req.URL.Path, RawQuery: req.URL.RawQuery}
		log.Printf("dir: %+v, redirect to %s", dir, u.String())
		http.Redirect(rw, req, u.String(), http.StatusSeeOther)
		return
	}

	d.next.ServeHTTP(rw, req)
}
