package proxy

import (
	"fmt"
	"testing"
)

func Test_getProxyAuthRealm(t *testing.T) {
	d := &DockerAuthProxy{
		ProxyAddress: "https://127.0.0.1:5000",
	}
	d.getProxyAuthRealm()
	fmt.Println(d.authRealmAddress)
	fmt.Println(d.authRealmType)
}
