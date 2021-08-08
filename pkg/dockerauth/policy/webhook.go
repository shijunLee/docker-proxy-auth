package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/shijunLee/docker-proxy-auth/pkg/common"
	"github.com/shijunLee/docker-proxy-auth/pkg/utils"
)

type WebHookAuth struct {
	RequestMethod      string
	KeyIn              string
	CustomHeader       map[string]string
	Endpoint           string
	InsecureSkipVerify bool
	PrivateKeyPath     string
	RootCAPath         string
	CertificatePath    string
	// support form application/json
	ContentType string
}

// AuthorizeUserResourceScope do webhook auth request
func (w *WebHookAuth) AuthorizeUserResourceScope(authInfo *common.AuthRequestInfo) ([]string, error) {
	httpClient := utils.NewHttpRequest()
	httpClient.InsecureSkipVerifyTLS = w.InsecureSkipVerify
	httpClient.CertPath = w.CertificatePath
	httpClient.PrivateKeyPath = w.PrivateKeyPath
	httpClient.RootCAPath = w.RootCAPath
	authRequest, err := http.NewRequest(w.RequestMethod, w.Endpoint, nil)
	if err != nil {
		return nil, err
	}
	// not support query param for this request
	if strings.ToLower(w.KeyIn) == "body" {
		if strings.ToLower(w.ContentType) == "form" {
			authRequest.Body = io.NopCloser(bytes.NewBufferString(authInfo.BuildFormBody()))
		} else if strings.ToLower(w.ContentType) == "application/json" {
			authRequest.Body = io.NopCloser(bytes.NewBuffer([]byte(authInfo.BuildJsonBody())))
		}
	} else {
		requestUrl, err := url.Parse(w.Endpoint)
		if err != nil {
			return nil, err
		}
		requestUrl.RawQuery = authInfo.BuildQuery()
		w.Endpoint = requestUrl.String()
	}
	for k, v := range w.CustomHeader {
		authRequest.Header.Set(k, v)
	}
	res, err := httpClient.Do(authRequest)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		message := fmt.Sprintf("auth fail for user:%s", authInfo.Account)
		if res.Body != nil {
			resData, err := ioutil.ReadAll(res.Body)
			if err == nil {
				message = string(resData)
			}
		}
		return nil, errors.New(message)
	}
	return authInfo.Actions, nil
}
