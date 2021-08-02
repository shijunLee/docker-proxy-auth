package cache

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/docker/distribution/registry/auth/token"
	lru "github.com/hashicorp/golang-lru"
)

type AuthCache struct {
	cache     *lru.Cache
	cleanTime *time.Ticker
}

func NewAuthCache() *AuthCache {
	lruCache, err := lru.New(500)
	if err != nil {
		panic(err)
	}
	var result = &AuthCache{
		cache:     lruCache,
		cleanTime: time.NewTicker(5 * time.Second),
	}
	go result.cleanExpirationToken()
	return result
}

func (c *AuthCache) cleanExpirationToken() {
	for {
		<-c.cleanTime.C
		var keys = c.cache.Keys()
		for _, key := range keys {
			tokenObject, ok := c.cache.Get(key)
			if !ok {
				continue
			}
			tokenInfo, ok := tokenObject.(token.Token)
			if !ok {
				continue
			}
			now := time.Now().UTC().Unix()
			expirationTime := now + int64(time.Duration(10*time.Second).Seconds())
			if tokenInfo.Claims.Expiration > expirationTime {
				c.cache.Remove(key)
			}
		}
	}
}

//SetAuthToken add auth token to lru cache
func (c *AuthCache) SetAuthToken(username, resourceType, name, string, action []string, token token.Token) {
	action = sort.StringSlice(action)
	actionString := strings.Join(action, ",")
	key := fmt.Sprintf("%s:%s:%s:%s", username, resourceType, name, actionString)
	_ = c.cache.Add(key, token)
}

//GetAuthToken get Auth token from lru cache
func (c *AuthCache) GetAuthToken(username, scope, repo, action []string) (string, bool) {
	action = sort.StringSlice(action)
	actionString := strings.Join(action, ",")
	key := fmt.Sprintf("%s:%s:%s:%s", username, scope, repo, actionString)
	value, ok := c.cache.Get(key)
	if ok {
		if valuestr, ok := value.(string); ok {
			return valuestr, true
		}
	}
	return "", false
}
