package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
)

type EnvResponse struct {
	AuthClientUrl       string `json:"authProviderURL"`
	AuthClientRealm     string `json:"authClientRealm"`
	AuthClientId        string `json:"authClientID"`
	ClassificationLevel string `json:"classificationLevel"`
}

func GetEnv() (EnvResponse, error) {
	apiURL := os.Getenv("API_URL")
	resp, err := http.Get(apiURL + "/env")
	if err != nil {
		return EnvResponse{}, err
	}

	envData := EnvResponse{}
	responseData, err := io.ReadAll(resp.Body)
	if err != nil {
		return EnvResponse{}, err
	}

	err = json.Unmarshal(responseData, &envData)
	if err != nil {
		return EnvResponse{}, err
	}

	return envData, nil
}

type Credentials struct {
	AccessToken string `json:"access_token"`
}
type QueryRequestBody struct {
	Query string `json:"query"`
}

func GetAPI(writer io.Writer) {

	// apiURL := os.Getenv("API_URL")
	jsonData := QueryRequestBody{
		Query: `{query: getUsers{
			id
			email
			firstName
			lastName
			} }`,
	}

	creds := "/Users/andrewalgard/projects/oidcli/.tmp/credentials.json"
	data, err := os.ReadFile(creds)
	if err != nil {
		panic(err)
	}
	token := Credentials{}
	err = json.Unmarshal(data, &token)
	if err != nil {
		panic(err)
	}
	client := http.Client{}
	jsonValue, _ := json.Marshal(jsonData)
	req, err := http.NewRequest("POST", "http://localhost:4000/graphql", bytes.NewBuffer(jsonValue))
	if err != nil {
		panic(err) //Handle Error
	}
	var builder strings.Builder
	builder.WriteString("Bearer ")
	builder.WriteString(token.AccessToken)
	req.Header.Set("Authorization", builder.String())
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	responseData, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	_, err = writer.Write(responseData)
	if err != nil {
		panic(err)
	}

}
