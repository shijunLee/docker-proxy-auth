package userauth

import (
	"crypto/tls"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

type LDAPServerConfig struct {
	ServerAddress      string
	InsecureSkipVerify bool
	BaseDN             string
	//TODO use go template for this
	Filter string
}

func (l *LDAPServerConfig) ActionLdapLogin(username, password string) error {

	conn, err := ldap.DialTLS("tcp", l.ServerAddress, &tls.Config{
		InsecureSkipVerify: l.InsecureSkipVerify,
	})
	if err != nil {
		//Err(ctx, ERROR_LDAP, "Ldap server disconnect.", err)
		return err
	}
	defer conn.Close()

	err = conn.Bind(username, password)
	if err != nil {
		//Err(ctx, ERROR_PASSWORD, "Password error.", err)
		return err
	}

	sql := ldap.NewSearchRequest(l.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.DerefAlways,
		0,
		0,
		false,
		fmt.Sprintf("(sAMAccountName=%s)", username),
		[]string{"sAMAccountName", "displayName", "mail", "mobile", "employeeID", "givenName"},
		nil)

	var cur *ldap.SearchResult

	if cur, err = conn.Search(sql); err != nil {
		//	Err(ctx, ERROR_LDAP, "Ldap server search failed.", err)
		return err
	}

	if len(cur.Entries) == 0 {
		//	Err(ctx, ERROR_NOUSER, "Not found user.", nil)
		return err
	}

	var result = struct {
		Name       string `json:"name"`
		Account    string `json:"account"`
		Email      string `json:"email"`
		Phone      string `json:"phone"`
		EmployeeId string `json:"employeeId"`
	}{
		Name:       cur.Entries[0].GetAttributeValue("givenName"),
		Account:    cur.Entries[0].GetAttributeValue("sAMAccountName"),
		Email:      cur.Entries[0].GetAttributeValue("mail"),
		Phone:      cur.Entries[0].GetAttributeValue("mobile"),
		EmployeeId: cur.Entries[0].GetAttributeValue("employeeID"),
	}
	fmt.Println(result)
	//Suc(ctx, &result)
	return nil
}
