package dimdanredirect

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// Config holds configuration to be passed to the plugin
type Config struct {
	DimdanDomain         string
	TakeawayDomain       string
	ShopDomain           string
	SDeliveryDomain      string
	StoreDirectoryDomain string
	Key                  string
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
	key                  string
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
	if config.Key == "" {
		return nil, fmt.Errorf("Key cannot be empty")
	}
	return &DimdanRedirect{
		next:                 next,
		name:                 name,
		dimdanDomain:         config.DimdanDomain,
		takeawayDomain:       config.TakeawayDomain,
		shopDomain:           config.ShopDomain,
		sDeliveryDomain:      config.SDeliveryDomain,
		storeDirectoryDomain: config.StoreDirectoryDomain,
		key:                  config.Key,
	}, nil
}

func (d *DimdanRedirect) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	queryValues := req.URL.Query()

	x, ok := queryValues["x"]
	if ok {
		rawQuery := d.decrypt(x[0])
		queryValues, _ = url.ParseQuery(rawQuery)
		req.URL.RawQuery = queryValues.Encode()
	}

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

func (d *DimdanRedirect) decrypt(text string) string {
	key := []byte(d.key)

	parts := strings.Split(text, "::")
	iv, _ := hex.DecodeString(parts[0])
	encryptedStr, _ := hex.DecodeString(parts[1])

	result := make([]byte, 10000)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println("aes.NewCipher(key) error, err: ", err.Error())
		return ""
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(result, encryptedStr)

	var trimResult []byte
	for i := range result {
		if result[i] == 0 {
			break
		}
		trimResult = append(trimResult, result[i])
	}

	return string(trimResult)
}

func (d *DimdanRedirect) encrypt(text string) string {
	key := []byte(d.key)
	plaintext := []byte(text)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println("aes.NewCipher(key) error, err: ", err.Error())
		return ""
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Println("io.ReadFull error, err: ", err.Error())
		return ""
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	encodedStr := hex.EncodeToString(iv) + "::" + hex.EncodeToString(ciphertext[aes.BlockSize:])
	return encodedStr
}
