package user

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type UserInfo struct {
	Sid       string `json:"bro_sid"`
	Sub       string `json:"bro_sub"`
	UserName  string `json:"bro_name"`
	UserEmail string `json:"bro_email"` //can be empty!
}

func (u *UserInfo) String() string {
	return fmt.Sprintf("UserInfo{sid=%s, sub=%s, name=%s, email=%s}", u.Sid, u.Sub, u.UserName, u.UserEmail)
}

func (u *UserInfo) ToInnerJwtClaims() map[string]string {
	// Marshal the struct to JSON
	jsonData, err := json.Marshal(u)
	if err != nil {
		log.Panicln("Failed to write JSON")
	}
	var m map[string]string
	err = json.Unmarshal(jsonData, &m)
	if err != nil {
		log.Panicln("Failed to read JSON")
	}
	return m
}

// Legacy functions for backward compatibility
// These are deprecated and will be removed in future versions
// Use UserManager instead

// InitIpMasks is deprecated. Use NewUserManager() instead.
func InitIpMasks() {
	// This function is kept for backward compatibility but does nothing
	// The UserManager handles IP mask initialization automatically
}

// Legacy function for backward compatibility
// This is deprecated and will be removed in future versions
// Use UserManager.ResolveUserInfoFromRequest() instead.
func ResolveUserInfoFromRequest(r *http.Request, userManager *UserManager) *UserInfo {
	return userManager.ResolveUserInfoFromRequest(r)
}

// Helper functions moved to user-manager.go
