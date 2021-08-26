package policy

import (
	"gorm.io/gorm"
)

//TODO use gorm support this for mysql sqlite pg etc/
type Policy struct {
	gorm.Model
	Username  string   `json:"string"`
	RepoName  string   `json:"repoName"`
	Operation string   `json:"operation"`
	Actions   []string `json:"actions"`
	Type      string   `json:"type"`
}
