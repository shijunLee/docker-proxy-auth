module github.com/shijunLee/docker-proxy-auth

go 1.16

require (
	github.com/caarlos0/env v3.5.0+incompatible
	github.com/docker/distribution v2.7.1+incompatible
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7
	github.com/go-ldap/ldap/v3 v3.3.0
	github.com/go-oauth2/oauth2/v4 v4.4.1
	github.com/golang-jwt/jwt/v4 v4.0.0
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/hashicorp/golang-lru v0.5.4
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/spf13/cobra v1.2.1
	github.com/spf13/viper v1.8.1
	go.uber.org/zap v1.18.1
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gorm.io/gorm v1.21.14
	k8s.io/apimachinery v0.22.1
	k8s.io/client-go v0.21.3
	sigs.k8s.io/controller-runtime v0.9.6
	sigs.k8s.io/yaml v1.2.0
)
