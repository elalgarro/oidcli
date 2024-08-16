package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

func getServerUrl() string {
	var builder strings.Builder
	port, ok := os.LookupEnv("TMP_SERVER_PORT")
	if !ok {
		port = "8183"
	}
	builder.WriteString("http://localhost:")
	builder.WriteString(port)
	return builder.String()
}

func getProvider(envData EnvResponse) *oidc.Provider {
	var builder strings.Builder
	builder.WriteString(strings.TrimSuffix(envData.AuthClientUrl, "/"))
	builder.WriteString("/realms/")
	builder.WriteString(envData.AuthClientRealm)
	provider, err := oidc.NewProvider(context.TODO(), builder.String())
	if err != nil {
		panic(err)
	}
	return provider
}

func getOauth2Config(provider *oidc.Provider, redirectURL string, clientId string) oauth2.Config {

	return oauth2.Config{
		ClientID:    clientId,
		RedirectURL: redirectURL,
		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}
}

func main() {
	if len(os.Args) > 1 {
		GetAPI()
		return
	}
	godotenv.Load()

	envData, err := GetEnv()
	if err != nil {
		os.Stderr.WriteString(err.Error())
		os.Exit(1)
		return
	}
	serverUrl := getServerUrl()
	redirectURL := fmt.Sprintf("%s/callback", serverUrl)
	provider := getProvider(envData)

	authConfig := getOauth2Config(provider, redirectURL, envData.AuthClientId)

	authCodeState, err := AuthorizationURL(&authConfig)
	if err != nil {
		panic(err)
	}

	ch := make(chan string)
	var wg sync.WaitGroup

	wg.Add(1)
	fmt.Println("Starting temporary server")
	go StartTempServer(ServerConfig{ch, &wg, &authConfig, *authCodeState, authCodeState.CodeVerifier, provider})

	go func() {
		wg.Wait()
		close(ch)
		fmt.Println("Succsessfully Logged in!")
		fmt.Println("Credentials were stored in this project's .tmp directory")
		fmt.Println("You can close the browser window now")
	}()

	for status := range ch {
		if status == "running" {
			fmt.Println("Opening Browser to provided auth URL")
			exec.Command("open", authCodeState.URL).Start()
		} else if status == "error" {
			panic("failure")
		}
	}

	output, err := json.Marshal(envData)
	if err != nil {
		os.Stderr.WriteString(err.Error())
		os.Exit(1)
		return
	}

	os.Stdout.WriteString(string(output))
}

type AuthURL struct {
	URL          string
	State        string
	CodeVerifier string
}

func (u *AuthURL) String() string {
	return u.URL
}

func AuthorizationURL(config *oauth2.Config) (*AuthURL, error) {
	codeVerifier, verifierErr := randomBytesInHex(32) // 64 character string here
	if verifierErr != nil {
		return nil, fmt.Errorf("could not create a code verifier: %v", verifierErr)
	}
	sha2 := sha256.New()
	io.WriteString(sha2, codeVerifier)
	codeChallenge := base64.RawURLEncoding.EncodeToString(sha2.Sum(nil))

	state, stateErr := randomBytesInHex(24)
	if stateErr != nil {
		return nil, fmt.Errorf("could not generate random state: %v", stateErr)
	}

	authUrl := config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
	)

	return &AuthURL{
		URL:          authUrl,
		State:        state,
		CodeVerifier: codeVerifier,
	}, nil
}

func randomBytesInHex(count int) (string, error) {
	buf := make([]byte, count)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return "", fmt.Errorf("could not generate %d random bytes: %v", count, err)
	}

	return hex.EncodeToString(buf), nil
}
