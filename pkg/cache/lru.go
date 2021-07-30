package cache

import (
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

func (c *AuthCache) GetAuthToken(username, scope, repo, action string) string {
	return ""
}
