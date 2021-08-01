package userauth

import (
	"context"
	"net/http"

	"github.com/shijunLee/docker-proxy-auth/pkg/utils"
)

type BasicAuth struct {
	Endpoint           string
	RequestMethod      string
	InsecureSkipVerify bool
	PrivateKeyPath     string
	RootCAPath         string
	CertificatePath    string
	CustomHeader       map[string]string
}

func (b *BasicAuth) AuthUser(context context.Context, username, password string) bool {
	var customHeader = http.Header{}
	for k, v := range b.CustomHeader {
		if k != "" {
			customHeader.Set(k, v)
		}
	}

	httpUtil := &utils.HttpUtil{
		Username:              username,
		Password:              password,
		RootCAPath:            b.RootCAPath,
		PrivateKeyPath:        b.PrivateKeyPath,
		CertPath:              b.CertificatePath,
		InsecureSkipVerifyTLS: b.InsecureSkipVerify,
		Header:                customHeader,
	}
	req, err := http.NewRequest(b.RequestMethod, b.Endpoint, nil)
	if err != nil {
		return false
	}
	res, err := httpUtil.Do(req)
	if err != nil {
		return false
	}
	if res.StatusCode == 200 {
		return true
	}
	return false
}
