package dns

import (
	"context"
	"fmt"
	"math/rand"
	"strings"

	"github.com/Pallinder/go-randomdata"
)

// Combination of space, tab, newline, etc...
const WHITESPACES = `
  				  
			 
			`

type TestToken struct {
	*Token
	records  []string
	hasToken bool
}

func TTokens(prefix string, count int) []TestToken {
	var tokens []TestToken

	for _, url := range RandomUrls(count) {
		tok, err := RandomToken(prefix, url)
		if err != nil {
			panic(err)
		}

		txtRecords, hasToken := RandTXT(count, tok.String())

		tokens = append(tokens, TestToken{
			Token:    tok,
			records:  txtRecords,
			hasToken: hasToken,
		})
	}

	return tokens
}

// var monthAgo = time.Now().AddDate(0, -1, 0)
// var monthAhead = time.Now().AddDate(0, 1, 0)
// var setFormat = "2006-01-02"
// var parseFormat = "Monday 2 Jan 2006"

func RandomToken(prefix, url string) (*Token, error) {
	// time.Parse(parseFormat, randomdata.FullDateInRange(monthAgo.Format(setFormat), monthAhead.Format(setFormat)))
	return NewToken(url, prefix, nil)
}

func RandomUrls(n int) []string {
	var urls []string

	var protoMod = rand.Int()%10 + 1
	var subMod = rand.Int()%10 + 1
	var portMod = rand.Int()%10 + 1
	var preSMod = rand.Int()%10 + 1
	var postSMod = rand.Int()%10 + 1

	for i := 0; i < n; i++ {
		var proto string
		if i%protoMod == 0 {
			proto = fmt.Sprintf("%s://", randomdata.SillyName()[:5])
		}

		var subdom string
		if i%subMod == 0 {
			subdom = fmt.Sprintf("%s.", randomdata.SillyName())
		}

		var port string
		if i%portMod == 0 {
			port = fmt.Sprintf(":%d", rand.Int()%65535)
		}

		var randomSpacePre string
		if i%preSMod == 0 {
			randomSpacePre = WHITESPACES
		}

		var randomSpacePost string
		if i%postSMod == 0 {
			randomSpacePost = WHITESPACES
		}

		urls = append(urls,
			strings.ToLower(fmt.Sprintf(
				"%s%s%s%s%s.%s%s",
				randomSpacePre,
				proto,
				subdom,
				randomdata.SillyName(),
				randomdata.SillyName()[:3],
				port,
				randomSpacePost,
			)))
	}

	return urls
}

func RandTXT(n int, insert string) ([]string, bool) {
	var txt []string
	randi := randomdata.Number(0, 2*n)
	hasRecord := false
	var preSMod = rand.Int()%10 + 1
	var postSMod = rand.Int()%10 + 1

	for i := 0; i < n; i++ {
		if i == randi {
			txt = append(txt, insert)
			hasRecord = true
			continue
		}

		var randomSpacePre string
		if i%preSMod == 0 {
			randomSpacePre = WHITESPACES
		}

		var randomSpacePost string
		if i%postSMod == 0 {
			randomSpacePost = WHITESPACES
		}

		txt = append(txt, fmt.Sprintf(
			"%s%s%s",
			randomSpacePre,
			randomdata.SillyName(),
			randomSpacePost,
		))
	}

	return txt, hasRecord
}

type TestResolver struct {
	Values map[string][]string
	Tokens map[string]*Token
}

func (tr *TestResolver) LookupTXT(
	_ context.Context,
	name string,
) ([]string, error) {
	v, ok := tr.Values[name]
	if !ok {
		return nil, nil
	}

	return v, nil
}
