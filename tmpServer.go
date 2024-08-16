package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type ServerConfig struct {
	ch            chan string
	wg            *sync.WaitGroup
	authConfig    *oauth2.Config
	authCodeState AuthURL
	verifier      string
	provider      *oidc.Provider
}

func StartTempServer(config ServerConfig) {
	port, ok := os.LookupEnv("TMP_SERVER_PORT")
	if !ok {
		port = "8183"
	}
	server := http.Server{
		Addr:           fmt.Sprintf(":%s", port),
		Handler:        nil,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	cb := OAuthRedirectHandler{
		State:        config.authCodeState.State,
		CodeVerifier: config.verifier,
		ch:           config.ch,
		wg:           config.wg,
		OAuthConfig:  config.authConfig,
		provider:     config.provider,
	}
	http.HandleFunc("/callback", cb.ServeHTTP)
	go func() {
		if err := server.ListenAndServe(); err != nil {
			fmt.Println(err.Error())
			config.ch <- "error"
		}
	}()

	config.ch <- "running"

	go func() {
		config.wg.Wait()
		server.Shutdown(context.TODO())
		config.ch <- "shutdown"
	}()

}

const (
	QUERY_STATE = "state"
	QUERY_CODE  = "code"
)

type OAuthRedirectHandler struct {
	State        string
	CodeVerifier string
	ch           chan string
	wg           *sync.WaitGroup
	OAuthConfig  *oauth2.Config
	provider     *oidc.Provider
}

func textResponse(rw http.ResponseWriter, status int, body string) {
	rw.Header().Add("Content-Type", "text/plain")
	rw.WriteHeader(status)
	io.WriteString(rw, body)
}

func (h *OAuthRedirectHandler) ServeHTTP(rw http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()

	state := query.Get(QUERY_STATE)
	// prevent timing attacks on state
	if subtle.ConstantTimeCompare([]byte(h.State), []byte(state)) == 0 {
		textResponse(rw, http.StatusBadRequest, "Invalid State")
		return
	}

	code := query.Get(QUERY_CODE)
	if code == "" {
		textResponse(rw, http.StatusBadRequest, "Missing Code")
		return
	}
	fmt.Println(request.Context())
	token, err := h.OAuthConfig.Exchange(
		request.Context(),
		code,
		oauth2.SetAuthURLParam("code_verifier", h.CodeVerifier),
	)
	if err != nil {
		textResponse(rw, http.StatusInternalServerError, err.Error())
		return
	}
	stringy := ParseToken(token, h.provider, h.OAuthConfig)
	f, err := os.Create("/Users/andrewalgard/projects/oidcli/.tmp/credentials.json")
	if err != nil {
		panic(err)
	}
	defer h.wg.Done()
	defer f.Close()
	d, err := json.Marshal(token)
	if err != nil {
		panic(err)
	}
	f.Write(d)

	// probably do something more legit with this token...
	textResponse(rw, http.StatusOK, stringy)
}

func ParseToken(token *oauth2.Token, provider *oidc.Provider, config *oauth2.Config) string {

	oidcConfig := oidc.Config{
		ClientID: config.ClientID,
	}
	verifier := provider.Verifier(&oidcConfig)
	rawId, ok := token.Extra("id_token").(string)
	if !ok {
		panic("could not extract id token")
	}
	verified, err := verifier.Verify(context.TODO(), rawId)
	if err != nil {
		panic(err)
	}

	if !ok {
		fmt.Println("error getting id_token")
	}
	resp := struct {
		OAuth2Token   *oauth2.Token
		IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
	}{token, new(json.RawMessage)}
	if err := verified.Claims(&resp.IDTokenClaims); err != nil {
		fmt.Println("ooo nooo")
	}
	j, err := json.Marshal(&resp.IDTokenClaims)
	if err != nil {
		panic(err)
	}

	return string(j)
}
