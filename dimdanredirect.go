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

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func (d *DimdanRedirect) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	queryValues := req.URL.Query()
	urlType := ""
	urlTypeDomainMap := map[string][]string{
		"dine-in":   strings.Split(d.dimdanDomain, ","),
		"takeaway":  strings.Split(d.takeawayDomain, ","),
		"shop":      strings.Split(d.shopDomain, ","),
		"sdelivery": strings.Split(d.sDeliveryDomain, ","),
		"directory": strings.Split(d.storeDirectoryDomain, ","),
	}

	x, ok := queryValues["x"]
	if ok {
		rawQuery := d.decrypt(x[0])
		if rawQuery != "" {
			queryValues, _ = url.ParseQuery(rawQuery)
			req.URL.RawQuery = queryValues.Encode()
		}
	}

	// dimdan
	t, okT := queryValues["t"]
	m, okM := queryValues["m"]
	if okT && len(t) > 0 && okM && len(m) > 0 {
		urlType = "dine-in"
	}

	// takeaway
	takeaway, ok := queryValues["takeaway"]
	if ok && checkStringIsTrue(takeaway[0]) {
		urlType = "takeaway"
	}

	// shop
	shop, ok := queryValues["shop"]
	if ok && checkStringIsTrue(shop[0]) {
		urlType = "shop"
	}

	// sdelivery
	sdelivery, ok := queryValues["sdelivery"]
	if ok && checkStringIsTrue(sdelivery[0]) {
		urlType = "sdelivery"
	}

	// dir
	dir, ok := queryValues["dir"]
	if ok && checkStringIsTrue(dir[0]) {
		urlType = "directory"
	}

	if urlType != "" && !contains(urlTypeDomainMap[urlType], req.Host) {
		u := url.URL{
			Scheme:   "https",
			Host:     urlTypeDomainMap[urlType][0],
			Path:     req.URL.Path,
			RawQuery: "x=" + d.encrypt(req.URL.RawQuery),
		}

		log.Printf("redirect frmo %s", req.Host)
		log.Printf("redirect to %s", u.String())
		http.Redirect(rw, req, u.String(), http.StatusSeeOther)
		return
	}

	d.next.ServeHTTP(rw, req)
}

func (d *DimdanRedirect) decrypt(text string) string {
	key := []byte(d.key)

	parts := strings.Split(text, "::")
	if len(parts) != 2 {
		log.Println("x incorrect")
		return ""
	}
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

func checkStringIsTrue(value string) bool {
	if value == "true" || value == "1" {
		return true
	}
	return false
}
