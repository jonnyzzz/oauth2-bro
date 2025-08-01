package user

import "net/http"

// MockUserInfoProvider is a simple mock implementation for testing
type MockUserInfoProvider struct {
	userInfo *UserInfo
}

// NewMockUserInfoProvider creates a new mock user info provider
func NewMockUserInfoProvider() *MockUserInfoProvider {
	return &MockUserInfoProvider{
		userInfo: &UserInfo{
			Sid:       "mock-sid",
			Sub:       "mock-sub",
			UserName:  "mock-user",
			UserEmail: "mock@example.com",
		},
	}
}

// SetUserInfo sets the user info to return
func (m *MockUserInfoProvider) SetUserInfo(userInfo *UserInfo) {
	m.userInfo = userInfo
}

// ResolveUserInfoFromRequest always returns the configured user info
func (m *MockUserInfoProvider) ResolveUserInfoFromRequest(r *http.Request) *UserInfo {
	return m.userInfo
}
