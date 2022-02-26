package dns

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func init() {
	gob.Register(&Token{})
}

// Resolver is an interface which defines a method for resolving DNS TXT
// records.
type Resolver interface {
	// LookupTXT queries the DNS records with the domain name and returns the
	// TXT records for the associated domain.
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// NewToken creates a verification token for the given domain.
func NewToken(domain, key string, expiration *time.Duration) (*Token, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, errors.New("domain is required")
	}

	key = strings.TrimSpace(key)
	//nolint
	if len(key) > 166 {
		return nil, errors.New("key is too long; limit is 166 characters")
	}

	dom, err := url.Parse(domain)
	if err != nil {
		return nil, err
	}

	// Handle bare domain names by automatically prepending `https://`
	if dom.Host == "" {
		dom, err = url.Parse("https://" + domain)
		if err != nil || dom.Host == "" {
			return nil, errors.New("invalid domain")
		}
	}

	host := dom.Host
	if strings.Contains(dom.Host, ":") {
		// Strip the port off the domain
		host, _, err = net.SplitHostPort(dom.Host)
		if err != nil {
			return nil, err
		}
	}

	return (&Token{Domain: host, Key: key}).New(expiration)
}

// Token is a verification token for domain ownership.
type Token struct {
	Domain     string     `json:"domain"`
	Key        string     `json:"key"`
	Nonce      int64      `json:"nonce"`
	Created    time.Time  `json:"created"`
	ValidateBy time.Time  `json:"validate_by"`
	Validated  *time.Time `json:"validated,omitempty"`
	Updated    *time.Time `json:"updated,omitempty"`

	// hash is a cached value of the token hash
	// this is not encoded because it can be
	// easily re-created from the other fields
	hash string `json:"-"`
}

// Hash returns the hash of the token by concatenating the domain and the nonce
func (t *Token) Hash() string {
	if t.hash != "" {
		return t.hash
	}

	// Concatenate the domain and nonce
	data := []byte(
		strconv.Itoa(int(t.Created.Unix())) +
			t.Domain +
			strconv.Itoa(int(t.Nonce)),
	)

	// Hash the data
	sum := sha512.Sum512(data)

	// Encode the hash as base64
	t.hash = base64.StdEncoding.EncodeToString(sum[:])

	return t.hash
}

// String returns a string representation of the token which should be used
// in the DNS TXT record.
func (t *Token) String() string {
	if t.Key == "" {
		return t.Hash()
	}

	return fmt.Sprintf("%s=%s", t.Key, t.Hash())
}

// New creates a new verification token for the domain and returns the
// new token.
func (t *Token) New(expiration *time.Duration) (*Token, error) {
	// Default to 7 days
	exp := time.Hour * 168
	if expiration != nil {
		exp = *expiration
	}

	// Generate a random nonce with sufficient entropy
	// MAX SIZE: INT64
	nonce, err := rand.Int(rand.Reader, big.NewInt(1<<63-1))
	if err != nil {
		return nil, err
	}

	return &Token{
		Domain:     t.Domain,
		Key:        t.Key,
		Nonce:      nonce.Int64(),
		Created:    time.Now(),
		ValidateBy: time.Now().Add(exp),
	}, nil
}

// Verify queries the DNS records with the token information and provided DNS
// resolver and returns true if the domain is verified.
func (t *Token) Verify(ctx context.Context, r Resolver) error {
	// Token has expired, re-generate
	if (t.Validated == nil && time.Now().After(t.ValidateBy)) ||
		(t.Validated != nil && t.Validated.After(t.ValidateBy)) {
		return errors.New("token expired; regenerate token")
	}

	// Don't verify more than once in a 24 hour period
	if t.Updated != nil && t.Updated.After(time.Now().AddDate(0, 0, -1)) {
		return nil
	}

	//nolint
	if len(t.Hash()) != 88 {
		return errors.New("invalid hash; regenerate token")
	}

	// Lookup the TXT records for the domain
	records, err := r.LookupTXT(ctx, t.Domain)
	if err != nil {
		return err
	}

	// Iterate over the records and check if the token is present
	for _, record := range records {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Trim off the space to ensure a valid check
			record = strings.TrimSpace(record)

			// Continue loop if hash doesn't match
			// NOTE: This would allow for multiple records with
			// the same key, but that's not a problem
			if record != t.String() {
				continue
			}

			return nil
		}
	}

	return errors.New("no token found for domain")
}
