package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/minio/minio/cmd/config/identity/openid"
	"github.com/minio/minio/pkg/env"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

const (
	EnvConfigURL = "OPENID_CONFIG_URL"
	EnvToken     = "OPENID_ACCESS_TOKEN"
)

// Validate token vs provider
func Validate(accessToken string, configURL string) (bool, error) {

	jp := new(jwtgo.Parser)
	jp.ValidMethods = []string{
		"RS256", "RS384", "RS512", "ES256", "ES384", "ES512",
		"RS3256", "RS3384", "RS3512", "ES3256", "ES3384", "ES3512",
	}

	tt, _ := jwtgo.Parse(accessToken, func(token *jwtgo.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwtgo.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		d := openid.DiscoveryDoc{}

		req, err := http.NewRequest(http.MethodGet, configURL, nil)
		if err != nil {
			return nil, err
		}
		clnt := http.Client{}

		r, err := clnt.Do(req)
		if err != nil {
			clnt.CloseIdleConnections()
			return nil, err
		}
		defer r.Body.Close()

		if r.StatusCode != http.StatusOK {
			return nil, errors.New(r.Status)
		}
		dec := json.NewDecoder(r.Body)
		if err = dec.Decode(&d); err != nil {
			return nil, err
		}

		resp, err := clnt.Get(d.JwksURI)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, errors.New(resp.Status)
		}

		var jwk openid.JWKS
		if err = json.NewDecoder(resp.Body).Decode(&jwk); err != nil {
			return nil, err
		}

		var kk crypto.PublicKey
		for _, key := range jwk.Keys {
			kk, err = key.DecodePublicKey()
			if err != nil {
				return nil, err
			}
		}

		pubKey := kk.(*rsa.PublicKey)

		return pubKey, nil

	})

	//fmt.Println(tt)
	return tt.Valid, nil
}

// Authorize token based on policy
func Authorize(accessToken string) (bool, error) {
	ctx := context.Background()

	// Define a simple policy.
	module := `
		package example

		default allow = false

		allow {
			tk := io.jwt.decode(input.token)
			groups := tk[1]["wlcg.groups"][_]
			groups == "/escape/cms"
		}
	`

	// Compile the module. The keys are used as identifiers in error messages.
	compiler, err := ast.CompileModules(map[string]string{
		"example.rego": module,
	})

	// Create a new query that uses the compiled policy from above.
	rego := rego.New(
		rego.Query("data.example.allow"),
		rego.Compiler(compiler),
		rego.Input(
			map[string]interface{}{
				"token": accessToken,
			},
		),
	)
	// Run evaluation.
	rs, err := rego.Eval(ctx)

	if err != nil {
		// Handle error.
		return false, err
	}

	return rs[0].Expressions[0].Value.(bool), nil
}

func main() {

	// sample token string taken from the New example
	tokenString := env.Get(EnvToken, "")
	if tokenString == "" {
		panic(fmt.Errorf("Env OPENID_ACCESS_TOKEN is empty. Please insert a valid access token there"))
	}
	configURL := env.Get(EnvConfigURL, "https://iam-escape.cloud.cnaf.infn.it/.well-known/openid-configuration")

	isValid, err := Validate(tokenString, configURL)
	if err != nil {
		panic(err)
	}

	if !isValid {
		panic(fmt.Errorf("Access token not valid."))
	}

	// Authorize jwt with OPA
	isAuthorized, err := Authorize(tokenString)
	if err != nil {
		panic(err)
	}

	//fmt.Println(isAuthorized)

	// Return answer to k8s api server
}
