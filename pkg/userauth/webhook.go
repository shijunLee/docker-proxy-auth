package userauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/shijunLee/docker-proxy-auth/pkg/log"
	"github.com/shijunLee/docker-proxy-auth/pkg/utils"
	"go.uber.org/zap"
)

type WebHookAuth struct {
	RequestMethod      string
	KeyIn              string
	CustomHeader       map[string]string
	Endpoint           string
	InsecureSkipVerify bool
	PrivateKeyPath     string
	RootCAPath         string

	CertificatePath string
	// support form application/json
	ContentType string
}

func (w *WebHookAuth) AuthUser(ctx context.Context, username, password string) bool {
	result, err := w.authUserInfo(ctx, username, password)
	if err != nil {
		log.Logger.Error("webhook auth user error", zap.Error(err))
	}
	return result
}

func (w *WebHookAuth) authUserInfo(ctx context.Context, username, password string) (bool, error) {

	httpClient := utils.NewHttpRequest()
	httpClient.InsecureSkipVerifyTLS = w.InsecureSkipVerify
	httpClient.CertPath = w.CertificatePath
	httpClient.PrivateKeyPath = w.PrivateKeyPath
	httpClient.RootCAPath = w.RootCAPath
	authRequest, err := http.NewRequest(w.RequestMethod, w.Endpoint, nil)
	if err != nil {
		return false, err
	}
	// not support query param for this request
	if strings.ToLower(w.KeyIn) == "header" {
		authRequest.SetBasicAuth(username, password)
	} else if strings.ToLower(w.KeyIn) == "body" {
		if strings.ToLower(w.ContentType) == "form" {
			var values = &url.Values{}
			values.Set("username", username)
			values.Set("password", password)
			authRequest.Body = io.NopCloser(bytes.NewBufferString(values.Encode()))
		} else if strings.ToLower(w.ContentType) == "application/json" {
			var bodyMap = map[string]string{}
			bodyMap["username"] = username
			bodyMap["password"] = password
			bodyData, _ := json.Marshal(bodyMap)
			authRequest.Body = io.NopCloser(bytes.NewBuffer(bodyData))
		}
	}
	for k, v := range w.CustomHeader {
		authRequest.Header.Set(k, v)
	}
	res, err := httpClient.Do(authRequest)
	if err != nil {
		return false, err
	}
	if res.StatusCode != 200 {
		message := fmt.Sprintf("auth fail for user:%s", username)
		if res.Body != nil {
			resData, err := ioutil.ReadAll(res.Body)
			if err == nil {
				message = string(resData)
			}
		}
		return false, errors.New(message)
	}
	return true, nil

}
