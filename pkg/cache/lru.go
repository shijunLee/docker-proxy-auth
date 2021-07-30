package cache

import (
	"fmt"

	lru "github.com/hashicorp/golang-lru"
)

type AuthCache struct {
	cache *lru.Cache
}

func NewAuthCache() *AuthCache {
	lruCache, err := lru.New(500)
	if err != nil {
		panic(err)
	}
	return &AuthCache{
		cache: lruCache,
	}
}

//SetAuthToken add auth token to lru cache
func (c *AuthCache) SetAuthToken(username, scope, repo, action, token string) {
	key := fmt.Sprintf("%s:%s:%s:%s", username, scope, repo, action)
	_ = c.cache.Add(key, token)
}

//GetAuthToken get Auth token from lru cache
func (c *AuthCache) GetAuthToken(username, scope, repo, action string) (string, bool) {
	key := fmt.Sprintf("%s:%s:%s:%s", username, scope, repo, action)
	value, ok := c.cache.Get(key)
	if ok {
		if valuestr, ok := value.(string); ok {
			return valuestr, true
		}
	}
	return "", false

}
