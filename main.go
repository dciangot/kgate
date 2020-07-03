package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/minio/minio/cmd/config/identity/openid"
	"github.com/minio/minio/pkg/env"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	cache "github.com/patrickmn/go-cache"
)

const (
	EnvConfigURL = "OPENID_CONFIG_URL"
	EnvToken     = "OPENID_ACCESS_TOKEN"
)

var c *cache.Cache

// Validate token vs provider
func Validate(accessToken string, configURL string, c *cache.Cache) (bool, error) {

	jp := new(jwtgo.Parser)
	jp.ValidMethods = []string{
		"RS256", "RS384", "RS512", "ES256", "ES384", "ES512",
		"RS3256", "RS3384", "RS3512", "ES3256", "ES3384", "ES3512",
	}

	tt, _ := jwtgo.Parse(accessToken, func(token *jwtgo.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwtgo.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		pub, found := c.Get("key")
		if found {
			//fmt.Println("Using cached pubKey")
			return pub, nil
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

		c.Set("key", pubKey, cache.DefaultExpiration)

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

type TokenReviewSpec struct {
	Token string `json:"token"`
}

type TokenReviewUser struct {
	Username string   `json:"username"`
	UID      string   `json:"uid,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	Extra    []string `json:"extra,omitempty"`
}

type TokenReviewStatus struct {
	Authenticated bool            `json:"authenticated"`
	User          TokenReviewUser `json:"user,omitempty"`
}

type TokenReview struct {
	ApiVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Spec       TokenReviewSpec   `json:"spec,omitempty"`
	Status     TokenReviewStatus `json:"status,omitempty"`
}

type GroupClaims struct {
	Groups []string `json:"wlcg.groups"`
	jwtgo.StandardClaims
}

func main() {

	c = cache.New(5*time.Minute, 10*time.Minute)

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {

		decoder := json.NewDecoder(req.Body)
		var review TokenReview

		if err := decoder.Decode(&review); err != nil {
			panic(err)
		}

		tokenString := review.Spec.Token
		if tokenString == "" {
			panic(fmt.Errorf("Token is empty. Please insert a valid access token."))
		}
		configURL := env.Get(EnvConfigURL, "https://iam-escape.cloud.cnaf.infn.it/.well-known/openid-configuration")

		isValid, err := Validate(tokenString, configURL, c)
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

		fmt.Println(isAuthorized)

		var parser jwtgo.Parser
		tokenParsed, _, err := parser.ParseUnverified(tokenString, &GroupClaims{})

		groups := []string{}
		if claims, ok := tokenParsed.Claims.(*GroupClaims); ok {
			groups = claims.Groups
		} else {
			panic(fmt.Errorf("Cannot get token information"))
		}

		response := TokenReview{
			ApiVersion: "authentication.k8s.io/v1beta1",
			Kind:       "TokenReview",
			Status: TokenReviewStatus{
				Authenticated: isAuthorized,
				User: TokenReviewUser{
					Username: "admin",
					Groups:   groups,
				},
			},
		}
		responseString, err := json.Marshal(response)

		io.WriteString(w, string(responseString))
	})

	// One can use generate_cert.go in crypto/tls to generate cert.pem and key.pem.
	log.Printf("About to listen on 8443. Go to https://127.0.0.1:8443/")
	err := http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil)
	//err := http.ListenAndServe(":8443", nil)
	log.Fatal(err)
	// Return answer to k8s api server
}
