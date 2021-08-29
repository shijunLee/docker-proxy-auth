package database

import (
	"strings"

	"gorm.io/gorm"
)

//TODO use gorm support this for mysql sqlite pg etc.
type Policy struct {
	gorm.Model
	Username  string `json:"username" gorm:"index"`
	RepoName  string `json:"repoName"`
	Operation string `json:"operation"`
	Actions   string `json:"actions"` //TODO,convert this to a array
	Type      string `json:"type" gorm:"index"`
}

func (p *Policy) GetPolicyRepo() string {
	return p.RepoName
}
func (p *Policy) GetUsername() string {
	return p.Username
}
func (p *Policy) GetOperation() string { // start with or eq
	return p.Operation
}
func (p *Policy) GetAction() []string { // pull or push
	return strings.Split(p.Actions, ",")
}
func (p *Policy) GetType() string { // registry(get catalog) or repository
	return p.Type
}
