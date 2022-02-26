package dns

import (
	"context"
	"fmt"
	"testing"

	"github.com/Pallinder/go-randomdata"
)

func Test_Random_Tokens(t *testing.T) {
	prefix := randomdata.SillyName()

	t.Logf("prefix: %s", prefix)

	tokens := TTokens(prefix, 1000)

	for _, testToken := range tokens {
		valid := testToken.hasToken
		name := fmt.Sprintf("%s_%s_valid:%v", prefix, testToken.Token.Domain, valid)

		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			r := &TestResolver{
				Values: map[string][]string{
					testToken.Token.Domain: testToken.records,
				},
				Tokens: map[string]*Token{
					testToken.Token.Domain: testToken.Token,
				},
			}

			err := testToken.Token.Verify(ctx, r)
			if !valid && err == nil {
				t.Fatal("expected error")
			} else if valid && err != nil {
				t.Fatal(err)
			}
		})
	}
}
