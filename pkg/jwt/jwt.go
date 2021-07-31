package jwt

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/google/uuid"
)

type Algorithm string

const (
	HS256 Algorithm = "HS256"
	RS256 Algorithm = "RS256"
)

type jwtPayload struct {
	jwt.StandardClaims
	UserName string `json:"userName,omitempty"`
	Account  string `json:"account,omitempty"`
	Type     string `json:"type,omitempty"`
	Policy   string `json:"policy,omitempty"`
}

type JWTTokenInfo struct {
	UserName       string
	Account        string
	State          string
	Policy         string
	Type           string
	ExpirationTime *time.Time
}

type JWTConfig struct {
	Key             string
	PublicKey       *rsa.PublicKey
	PrivateKey      *rsa.PrivateKey
	ExpirationTime  int
	AlgorithmMethod Algorithm
	AuthDomain      string
	algorithm       jwt.SigningMethod
}

func NewJWTConfig(expirationTime int) *JWTConfig {

	// jwtAuthConfig := config.GlobalConfig.AuthConfig.JWTConfig
	// var jwtTime = jwtAuthConfig.ExpirationHour
	// if expirationTime != 0 {
	// 	jwtTime = expirationTime
	// }
	jwtConfig := &JWTConfig{
		// Logger:          logger,
		// Key:             jwtAuthConfig.Hs256Key,
		// ExpirationTime:  jwtTime,
		// AlgorithmMethod: Algorithm(jwtAuthConfig.AlgorithmMethod),
		// AuthDomain:      jwtAuthConfig.AuthDomain,
	}
	if jwtConfig.AlgorithmMethod == RS256 {
		var publicKey *rsa.PublicKey
		var privateKey *rsa.PrivateKey
		//var err error
		// if jwtAuthConfig.PrivateKeyPath != "" && (jwtAuthConfig.CertificatePath != "" || jwtAuthConfig.PublicKeyPath != "") {

		// 	if jwtAuthConfig.CertificatePath != "" {
		// 		keyPair, err := tls.LoadX509KeyPair(jwtAuthConfig.CertificatePath, jwtAuthConfig.PrivateKeyPath)
		// 		if err != nil {
		// 			panic(err)
		// 		}
		// 		if keyPair.Leaf == nil {
		// 			panic(errors.New("get cert key error"))
		// 		}
		// 		publicKey = keyPair.Leaf.PublicKey.(*rsa.PublicKey)
		// 		privateKey = keyPair.PrivateKey.(*rsa.PrivateKey)
		// 	} else {
		// 		publicKey = loadRSAPublicKeyFromDisk(jwtAuthConfig.PublicKeyPath)
		// 		privateKey = loadRSAPrivateKeyFromDisk(jwtAuthConfig.PrivateKeyPath)
		// 	}

		// } else {
		// 	privateKey, err = parsePEMEncodedPrivateKey([]byte(jwtAuthConfig.PrivateKey))
		// 	if err != nil {
		// 		panic(err)
		// 	}
		// 	if jwtAuthConfig.Certificate != "" {
		// 		certKey, err := parsePEMEncodedCert([]byte(jwtAuthConfig.Certificate))
		// 		if err != nil {
		// 			panic(err)
		// 		}
		// 		publicKey = certKey.PublicKey.(*rsa.PublicKey)

		// 	} else if jwtAuthConfig.PublicKey != "" {
		// 		var err error
		// 		publicKey, err = parsePEMEncodedPublicKey([]byte(jwtAuthConfig.PublicKey))
		// 		if err != nil {
		// 			panic(err)
		// 		}
		// 	} else {
		// 		panic(errors.New("not config public key or cert"))
		// 	}

		// }
		if privateKey == nil || publicKey == nil {
			panic(errors.New("not config public key or cert"))
		}
		jwtConfig.PublicKey = publicKey
		jwtConfig.PrivateKey = privateKey
	}
	var hs jwt.SigningMethod
	if jwtConfig.AlgorithmMethod == HS256 {
		hs = jwt.SigningMethodHS256
	} else if jwtConfig.AlgorithmMethod == RS256 {
		hs = jwt.SigningMethodRS256
	}
	jwtConfig.algorithm = hs
	return jwtConfig
}

func loadRSAPublicKeyFromDisk(location string) *rsa.PublicKey {
	keyData, e := ioutil.ReadFile(location)
	if e != nil {
		panic(e)
	}
	key, e := parsePEMEncodedPublicKey(keyData)
	if e != nil {
		panic(e)
	}
	return key
}

func loadRSAPrivateKeyFromDisk(location string) *rsa.PrivateKey {
	keyData, e := ioutil.ReadFile(location)
	if e != nil {
		panic(e)
	}
	key, e := parsePEMEncodedPrivateKey(keyData)
	if e != nil {
		panic(e)
	}
	return key
}

func parsePEMEncodedCert(pemdata []byte) (*x509.Certificate, error) {
	var cert tls.Certificate
	var skippedBlockTypes []string
	for {
		var certDERBlock *pem.Block
		certDERBlock, pemdata = pem.Decode(pemdata)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		} else {
			skippedBlockTypes = append(skippedBlockTypes, certDERBlock.Type)
		}
	}
	if len(cert.Certificate) == 0 {
		if len(skippedBlockTypes) == 0 {
			return nil, errors.New("tls: failed to find any PEM data in certificate input")
		}
		if len(skippedBlockTypes) == 1 && strings.HasSuffix(skippedBlockTypes[0], "PRIVATE KEY") {
			return nil, errors.New("tls: failed to find certificate PEM data in certificate input, but did find a private key; PEM inputs may have been switched")
		}
		return nil, fmt.Errorf("tls: failed to find \"CERTIFICATE\" PEM block in certificate input after skipping PEM blocks of the following types: %v", skippedBlockTypes)
	}
	return x509.ParseCertificate(cert.Certificate[0])
}

func parsePEMEncodedPublicKey(pemdata []byte) (*rsa.PublicKey, error) {
	decoded, _ := pem.Decode(pemdata)
	if decoded == nil {
		return nil, errors.New("no PEM data found")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(decoded.Bytes)
	if err != nil {

		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return pub, nil
}

func parsePEMEncodedPrivateKey(pemdata []byte) (*rsa.PrivateKey, error) {
	decoded, _ := pem.Decode(pemdata)
	if decoded == nil {
		return nil, errors.New("no PEM data found")
	}
	return x509.ParsePKCS1PrivateKey(decoded.Bytes)
}

func (j *JWTConfig) Token(data *oauth2.GenerateBasic, isGenRefresh bool) (access, refresh string, err error) {
	var expiresTime = data.TokenInfo.GetAccessCreateAt().Add(data.TokenInfo.GetAccessExpiresIn())
	var timeNow = time.Now().Unix()
	payload := &jwtPayload{
		StandardClaims: jwt.StandardClaims{
			Audience:  data.Client.GetID(),
			Subject:   data.UserID,
			ExpiresAt: expiresTime.Unix(),
			Issuer:    "tpaas",
			IssuedAt:  timeNow,
			NotBefore: timeNow,
			Id:        data.TokenInfo.GetScope(),
		},
	}
	jwtSigning := jwt.New(j.algorithm)
	jwtSigning.Claims = payload
	access, err = jwtSigning.SignedString(j.loadSignedKey())
	if err != nil {
		return "", "", err
	}
	refresh = ""
	if isGenRefresh {
		refresh = base64.URLEncoding.EncodeToString([]byte(uuid.NewSHA1(uuid.Must(uuid.NewRandom()), []byte(access)).String()))
		refresh = strings.ToUpper(strings.TrimRight(refresh, "="))
	}
	return access, refresh, nil
}

func (j *JWTConfig) loadSignedKey() interface{} {
	if j.algorithm == jwt.SigningMethodHS256 {
		return []byte(j.Key)
	} else if j.algorithm == jwt.SigningMethodRS256 {
		return j.PrivateKey
	} else {
		panic(errors.New("signing method not support"))
	}
}

func (j *JWTConfig) GetJWTToken(tokenInfo *JWTTokenInfo) (string, error) {
	now := time.Now().UTC()
	var timeNow = time.Now().Unix()
	expirationTime := tokenInfo.ExpirationTime
	if j.ExpirationTime > 0 {
		expTime := now.Add(time.Duration(j.ExpirationTime) * time.Hour)
		expirationTime = &expTime
	}
	payload := &jwtPayload{
		StandardClaims: jwt.StandardClaims{
			Audience:  j.AuthDomain,
			Subject:   tokenInfo.UserName,
			ExpiresAt: expirationTime.Unix(),
			Issuer:    "tpaas",
			IssuedAt:  timeNow,
			NotBefore: timeNow,
			Id:        tokenInfo.State,
		},
		UserName: tokenInfo.UserName,
		Account:  tokenInfo.Account,
		Policy:   tokenInfo.Policy,
		Type:     tokenInfo.Type,
	}
	jwtSigning := jwt.New(j.algorithm)
	jwtSigning.Claims = payload
	access, err := jwtSigning.SignedString(j.loadSignedKey())
	if err != nil {
		return "", err
	}
	return access, nil
}

func (j *JWTConfig) JWTVerify(tokenString string) (*JWTTokenInfo, error) {
	var pl = &jwtPayload{}

	_, err := jwt.ParseWithClaims(tokenString, pl, func(token *jwt.Token) (interface{}, error) {
		if j.algorithm == jwt.SigningMethodHS256 {
			return []byte(j.Key), nil
		} else if j.algorithm == jwt.SigningMethodRS256 {
			return j.PublicKey, nil
		} else {
			return nil, errors.New("not support signing method")
		}
	})
	if err != nil {
		return nil, err
	}

	if pl.Issuer != "tpaas" {
		return nil, errors.New("the token not issuer by tpaas")
	}

	result := &JWTTokenInfo{
		UserName: pl.UserName,
		Account:  pl.Account,
		Policy:   pl.Policy,
		State:    pl.Id,
		Type:     pl.Type,
	}
	return result, nil
}
