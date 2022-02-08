package domain

import "strings"

type RolePermissions struct {
	rolePermissions map[string][]string
}

func (p RolePermissions) IsAuthorizedFor(role, routeName string) bool {
	routeName = strings.TrimSpace(routeName)
	permissions := p.rolePermissions[role]
	for _, permission := range permissions {
		if permission == routeName {
			return true
		}
	}
	return false
}

func GetRolePermissions() RolePermissions {
	return RolePermissions{map[string][]string{
		"admin": {"GetAllCustomers", "GetCustomer", "NewAccount", "NewTransaction"},
		"user":  {"GetCustomer", "NewTransaction"},
	}}
}
