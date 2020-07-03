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
	"github.com/spf13/viper"
)

const (
	EnvOpenIDConfigURL = "OPENID_CONFIG_URL"
	EnvConfigOPA       = "OPA_POLICY_FILE"
)

var c *cache.Cache

// Validate token vs provider
func Validate(accessToken string, configURL string, c *cache.Cache) (bool, error) {

	jp := new(jwtgo.Parser)
	jp.ValidMethods = []string{
		"RS256", "RS384", "RS512", "ES256", "ES384", "ES512",
		"RS3256", "RS3384", "RS3512", "ES3256", "ES3384", "ES3512",
	}

	// Validate token against issuer
	tt, _ := jwtgo.Parse(accessToken, func(token *jwtgo.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwtgo.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// check if publicKey already in cache
		pub, found := c.Get("key")
		if found {
			//fmt.Println("Using cached pubKey")
			return pub, nil
		}

		// Retrieve Issuer metadata from discovery endpoint
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

		// Get Public Key from JWK URI
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

		// Return the rsa public key for the token validation
		pubKey := kk.(*rsa.PublicKey)

		c.Set("key", pubKey, cache.DefaultExpiration)

		return pubKey, nil

	})

	//fmt.Println(tt)
	return tt.Valid, nil
}

// Authorize token based on OPA policy
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
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Spec       TokenReviewSpec   `json:"spec,omitempty"`
	Status     TokenReviewStatus `json:"status,omitempty"`
}

type GroupClaims struct {
	Groups []string `json:"wlcg.groups"`
	jwtgo.StandardClaims
}

func main() {

	viper.SetConfigName("kgate_config") // name of config file (without extension)
	viper.SetConfigType("yaml")         // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath("/etc/kgate/")  // path to look for the config file in
	viper.AddConfigPath("$HOME/.kgate") // call multiple times to add many search paths
	viper.AddConfigPath(".")            // optionally look for config in the working directory

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if desired
		} else {
			// Config file was found but another error was produced
		}
	}

	configURL := env.Get(EnvOpenIDConfigURL, "")
	//configOPA := env.Get(EnvConfigOPA, "")

	// // NOT NEEDED YET
	// if configURL == "" && viper.IsSet("oidc.configURL") {
	// 	configURL = viper.GetString("oidc.configURL")
	// } else {
	// 	panic(fmt.Errorf("unable to get OIDC config URL from config file"))
	// }

	// if configOPA == "" && viper.IsSet("opa.configPath") {
	// 	configOPA = viper.GetString("oidc.configPath")
	// } else {
	// 	panic(fmt.Errorf("unable to get OPA policy file PATH from config file"))
	// }

	c = cache.New(5*time.Minute, 10*time.Minute)

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {

		decoder := json.NewDecoder(req.Body)
		var review TokenReview

		if err := decoder.Decode(&review); err != nil {
			msg := fmt.Sprintf("Unable to decode auth request: %s", err)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		tokenString := review.Spec.Token
		if tokenString == "" {
			msg := fmt.Sprintf("Token is empty. Please insert a valid access token")
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		isValid, err := Validate(tokenString, configURL, c)
		if err != nil {
			msg := fmt.Sprintf("Unable to validate token %s", err)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		if !isValid {
			http.Error(w, "Invalid access token", http.StatusBadRequest)
			return
		}

		// Authorize jwt with OPA
		isAuthorized, err := Authorize(tokenString)
		if err != nil {
			msg := fmt.Sprintf("Could not process access token for  authN/Z: %s", err)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		log.Println(tokenString, isAuthorized)

		var response TokenReview

		// Generate response for k8s APIServer
		if isAuthorized {
			var parser jwtgo.Parser
			tokenParsed, _, err := parser.ParseUnverified(tokenString, &GroupClaims{})
			if err != nil {
				msg := fmt.Sprintf("Unable to parse token %s", err)
				http.Error(w, msg, http.StatusBadRequest)
				return
			}

			groups := []string{}
			if claims, ok := tokenParsed.Claims.(*GroupClaims); ok {
				groups = claims.Groups
			} else {
				msg := fmt.Sprintf("Cannot get token information")
				http.Error(w, msg, http.StatusBadRequest)
				return
			}

			response = TokenReview{
				APIVersion: "authentication.k8s.io/v1beta1",
				Kind:       "TokenReview",
				Status: TokenReviewStatus{
					Authenticated: isAuthorized,
					User: TokenReviewUser{
						Username: "admin",
						Groups:   groups,
					},
				},
			}
		} else {
			response = TokenReview{
				APIVersion: "authentication.k8s.io/v1beta1",
				Kind:       "TokenReview",
				Status: TokenReviewStatus{
					Authenticated: isAuthorized,
				},
			}
		}
		responseString, err := json.Marshal(response)
		if err != nil {
			msg := fmt.Sprintf("Unable to format a valid response %s", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		io.WriteString(w, string(responseString))
	})

	// One can use utils/generate_cert.go to generate cert.pem and key.pem.
	log.Printf("About to listen on 8443. Go to https://localhost:8443/")
	err := http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil)
	//err := http.ListenAndServe(":8443", nil)
	log.Fatal(err)
}
