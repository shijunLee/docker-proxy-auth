package userauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/shijunLee/docker-proxy-auth/pkg/utils"
)

type GrantType string
type AuthorizeResponseType string
type TokenTypeHint string
type ContentType string
type CodeChallengeMethod string

const (
	AuthorizationCode         GrantType             = "authorization_code"
	RefreshToken              GrantType             = "refresh_token"
	AuthorizeResponseCode     AuthorizeResponseType = "code"
	AuthorizeResponseToken    AuthorizeResponseType = "token"
	TokenTypeHintAccessToken  TokenTypeHint         = "access_token"
	TokenTypeHintRefreshToken TokenTypeHint         = "refresh_token"
	ContentForm               ContentType           = "application/x-www-form-urlencoded"
	ContentJson               ContentType           = "application/json"
	CodeChallengePlain        CodeChallengeMethod   = "plain"
	CodeChallengeS256         CodeChallengeMethod   = "S256"
	standardAuthTokenKey                            = "Authorization"
)

type OAuth2 struct {
	Endpoint           string
	RequestMethod      string
	InsecureSkipVerify bool
	PrivateKeyPath     string
	RootCAPath         string
	CertificatePath    string
	ClientID           string
	ClientSecret       string
	Scope              string
}

type Token struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
	IdToken      string `json:"id_token,omitempty"`
}

func (i *OAuth2) AuthUser(ctx context.Context, username, password string) bool {
	ok, err := i.PasswordAuth(ctx, username, password)
	if !ok || err != nil {
		return false
	}
	return true
}

func (i *OAuth2) PasswordAuth(ctx context.Context, username, password string) (ok bool, err error) {
	_, err = i.passwordCredentialsToken(ctx, username, password)
	if err != nil {
		return false, err
	}
	// info, err := i.getUserInfo(token.AccessToken, "Bearer")
	// if err != nil {
	// 	return false, nil, err
	// }
	return true, nil
}

// func (i *OAuth2) getUserInfo(token, tokenType string) (*UserInfo, error) {
// 	headers := map[string]string{}
// 	headers["Authorization"] = fmt.Sprintf("%s %s", tokenType, token)
// 	useInfo := &UserInfo{}
// 	err := utils.HttpGetStruct(i.UserInfoEndPoint, headers, useInfo)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return useInfo, nil
// }

func (i *OAuth2) passwordCredentialsToken(ctx context.Context, username, password string) (*Token, error) {
	v := url.Values{
		"grant_type":    {"password"},
		"username":      {username},
		"password":      {password},
		"client_id":     {i.ClientID},
		"client_secret": {i.ClientSecret},
	}

	if len(i.Scope) > 0 {
		scopes := strings.Split(i.Scope, " ")
		if len(scopes) == 1 {
			scopes = strings.Split(i.Scope, ",")
		}
		v.Set("scope", strings.Join(scopes, " "))
	}
	headers := map[string]string{}
	headers["Content-Type"] = string(ContentForm)
	headers["Authorization"] = i.getAuthorizationBasic()
	token := &Token{}
	data, code, _, err := utils.HttpPost(i.Endpoint, headers, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, errors.New(string(data))
	}
	err = json.Unmarshal(data, token)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (i *OAuth2) getAuthorizationBasic() string {
	baseStr := fmt.Sprintf("%s:%s", i.ClientID, i.ClientSecret)
	base64Code := base64.StdEncoding.EncodeToString([]byte(baseStr))
	return fmt.Sprintf("Basic %s", base64Code)
}
