package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const SDKVersion = "admin-2.0.0-go"

const (
	actionUserGet            = "/users.get"
	actionUserCreate         = "/users.create"
	actionUserUpdate         = "/users.update"
	actionUserDelete         = "/users.delete"
	actionUserList           = "/users.list"
	actionUserSetPassword    = "/users.setPassword"
	actionUserChangePassword = "/users.changePassword"
	actionUserMetadataGet    = "/users.metadata.get"
	actionUserMetadataSet    = "/users.metadata.set"
	actionUserMetadataDelete = "/users.metadata.delete"
	actionMigrateUsers       = "/users.adminMigrateUsers"
	actionImpersonateStart   = "/users.adminImpersonate"
	actionImpersonateStop    = "/users.adminStopImpersonating"
)

const (
	secondFactorEmail = "emailCode"
	secondFactorSMS   = "smsCode"
)

const (
	languageEn = "en"
)

const (
	passwordAlgorithmBcrypt = "bcrypt"
	passwordAlgorithmSHA512 = "sha512"
)

type Client interface {
	CreateUser(req *CreateUserRequest) (*UserResponse, error)
	GetUser(req *GetUserRequest) (*UserResponse, error)
	DeleteUser(request *DeleteUserRequest) (*ActionStatusResponse, error)
	ListUsers(request *ListUsersRequest) (*ListUsersResponse, error)
	UpdateUser(request *UpdateUserRequest) (*UserResponse, error)
	SetUserPassword(request *SetUserPasswordRequest) (*ActionStatusResponse, error)
	ChangeUserPassword(request *ChangeUserPasswordRequest) (*ActionStatusResponse, error)
	GetAllUserMetadata(request *GetAllUserMetadataRequest) (*GetAllUserMetadataResponse, error)
	SetUserMetadata(request *SetUserMetadataRequest) (*ActionStatusResponse, error)
	DeleteUserMetadata(request *DeleteUserMetadataRequest) (*ActionStatusResponse, error)
	MigrateBcryptUsers(request *MigrateBcryptUsersRequest) (*MigrateUsersResponse, error)
	MigrateSha512Users(request *MigrateSha512UsersRequest) (*MigrateUsersResponse, error)
	ImpersonateStart(request *ImpersonateStartRequest) (*ImpersonateStartResponse, error)
	ImpersonateStop(request *ImpersonateStopRequest) (*ImpersonateStopResponse, error)
}

type UserResponse struct {
	UserID            string   `json:"id"`
	Status            string   `json:"status"`
	Username          string   `json:"username"`
	EmailAddress      string   `json:"emailAddress"`
	DisableMFA        bool     `json:"disableMfa"`
	AllowedMFAMethods []string `json:"allowedMfaMethods"`
	Language          string   `json:"language"`
	PhoneNumber       string   `json:"phoneNumber"`
}

type ActionStatusResponse struct {
	Status string `json:"status"`
}

type client struct {
	baseURL string
	client  *http.Client
	apiKey  string
}

func (c *client) request(action string, body io.Reader) (io.ReadCloser, error) {
	req, err := http.NewRequest("POST", c.baseURL+action, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", c.apiKey)
	req.Header.Set("X-SDK-Version", SDKVersion)

	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	// Handle Api Gateway errors
	if res.StatusCode == http.StatusInternalServerError ||
		res.StatusCode == http.StatusServiceUnavailable ||
		res.StatusCode == http.StatusGatewayTimeout ||
		res.StatusCode == http.StatusBadGateway ||
		res.StatusCode == http.StatusUnauthorized ||
		res.StatusCode == http.StatusForbidden {
		bodyBytes, err := io.ReadAll(res.Body)
		if err == nil {
			err := &ErrUnexpected{
				Message: fmt.Sprintf("HTTP %d - API error: %v", res.StatusCode, string(bodyBytes)),
			}

			return nil, err
		}

		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		errorResponse := &ErrorResponse{}

		// Decode the error response
		err = json.NewDecoder(res.Body).Decode(errorResponse)
		if err != nil {
			return nil, err
		}

		// Check the error type and return the appropriate error
		switch errorResponse.Message.Type {
		case "configError":
			return nil, &ErrInvalidConfig{errorResponse.Message.Message}
		case "bearerMalformed":
			return nil, &ErrBearerMalformed{errorResponse.Message.Message}
		case "userDeleteFailed":
			return nil, &ErrUserDeleteFailed{errorResponse.Message.Message}
		case "passwordInvalid":
			return nil, &ErrPasswordInvalid{errorResponse.Message.Message}
		case "userAlreadyImpersonated":
			return nil, &ErrUserAlreadyImpersonated{errorResponse.Message.Message}
		case "userNotImpersonated":
			return nil, &ErrUserNotImpersonated{errorResponse.Message.Message}
		case "notFound":
			return nil, &ErrNotFound{errorResponse.Message.Message}
		case "usernameAlreadyTaken":
			return nil, &ErrUsernameAlreadyTaken{errorResponse.Message.Message}
		case "userAlreadyExists":
			return nil, &ErrUserAlreadyExists{errorResponse.Message.Message}
		case "bearerExpired":
			return nil, &ErrBearerTokenExpired{errorResponse.Message.Message}
		case "sessionInvalid":
			return nil, &ErrSessionInvalid{errorResponse.Message.Message}
		default:
			return nil, &ErrUnexpected{fmt.Sprintf("Unexpected error.\nType: %v\nMessage: %v", errorResponse.Message.Type, errorResponse.Message.Message)}
		}
	}

	return res.Body, nil
}

type CitadelError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type ErrorResponse struct {
	Id      string       `json:"errorId,omitempty"`
	Message CitadelError `json:"error"`
}

type ErrUnexpected struct {
	Message string
}

func (e *ErrUnexpected) Error() string {
	return e.Message
}

type ErrInvalidConfig struct {
	Message string
}

func (e *ErrInvalidConfig) Error() string {
	return e.Message
}

type ErrBearerMalformed struct {
	Message string
}

func (e *ErrBearerMalformed) Error() string {
	return e.Message
}

type ErrUserDeleteFailed struct {
	Message string
}

func (e *ErrUserDeleteFailed) Error() string {
	return e.Message
}

type ErrPasswordInvalid struct {
	Message string
}

func (e *ErrPasswordInvalid) Error() string {
	return e.Message
}

type ErrUserAlreadyImpersonated struct {
	Message string
}

func (e *ErrUserAlreadyImpersonated) Error() string {
	return e.Message
}

type ErrUserNotImpersonated struct {
	Message string
}

func (e *ErrUserNotImpersonated) Error() string {
	return e.Message
}

type ErrNotFound struct {
	Message string
}

func (e *ErrNotFound) Error() string {
	return e.Message
}

type ErrUsernameAlreadyTaken struct {
	Message string
}

func (e *ErrUsernameAlreadyTaken) Error() string {
	return e.Message
}

type ErrUserAlreadyExists struct {
	Message string
}

func (e *ErrUserAlreadyExists) Error() string {
	return e.Message
}

type ErrBearerTokenExpired struct {
	Message string
}

func (e *ErrBearerTokenExpired) Error() string {
	return e.Message
}

type ErrSessionInvalid struct {
	Message string
}

func (e *ErrSessionInvalid) Error() string {
	return e.Message
}

type ClientConfig struct {
	BaseURL string
	APIKey  string
}

func NewClient(config *ClientConfig) Client {
	return &client{
		baseURL: config.BaseURL,
		client:  &http.Client{},
		apiKey:  config.APIKey,
	}
}

type CreateUserRequest struct {
	UserID       string `json:"userId"`
	Username     string `json:"username"`
	EmailAddress string `json:"emailAddress"`
	Language     string `json:"language"`
	Password     string `json:"password"`
}

type CreateUserResponse struct {
	User UserResponse `json:"user"`
}

func (c *client) CreateUser(req *CreateUserRequest) (*UserResponse, error) {
	return sendRequest(c, actionUserGet, req, func() *UserResponse {
		return &UserResponse{}
	})
}

type GetUserRequest struct {
	UserID string `json:"userId"`
}

func (c *client) GetUser(req *GetUserRequest) (*UserResponse, error) {
	return sendRequest(c, actionUserGet, req, func() *UserResponse {
		return &UserResponse{}
	})
}

type DeleteUserRequest struct {
	UserID string `json:"userId"`
}

func (c *client) DeleteUser(req *DeleteUserRequest) (*ActionStatusResponse, error) {
	return sendRequest(c, actionUserDelete, req, func() *ActionStatusResponse {
		return &ActionStatusResponse{}
	})
}

type ListUsersRequest struct {
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit"`
}

type ListUsersResponse struct {
	Users  []UserResponse `json:"items"`
	Cursor string         `json:"cursor,omitempty"`
}

func (c *client) ListUsers(req *ListUsersRequest) (*ListUsersResponse, error) {
	return sendRequest(c, actionUserList, req, func() *ListUsersResponse {
		return &ListUsersResponse{}
	})
}

type UpdateUserRequest struct {
	UserID            string   `json:"userId"`
	Username          string   `json:"username,omitempty"`
	EmailAddress      string   `json:"emailAddress,omitempty"`
	PhoneNumber       string   `json:"phoneNumber,omitempty"`
	DisableMFA        *bool    `json:"disableMfa,omitempty"`
	AllowedMFAMethods []string `json:"allowedMfaMethods,omitempty"`
}

func (c *client) UpdateUser(req *UpdateUserRequest) (*UserResponse, error) {
	return sendRequest(c, actionUserUpdate, req, func() *UserResponse {
		return &UserResponse{}
	})
}

type SetUserPasswordRequest struct {
	UserID   string `json:"userId"`
	Password string `json:"password"`
}

func (c *client) SetUserPassword(req *SetUserPasswordRequest) (*ActionStatusResponse, error) {
	return sendRequest(c, actionUserSetPassword, req, func() *ActionStatusResponse {
		return &ActionStatusResponse{}
	})
}

type ChangeUserPasswordRequest struct {
	UserID      string `json:"userId"`
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

func (c *client) ChangeUserPassword(req *ChangeUserPasswordRequest) (*ActionStatusResponse, error) {
	return sendRequest(c, actionUserChangePassword, req, func() *ActionStatusResponse {
		return &ActionStatusResponse{}
	})
}

type GetAllUserMetadataRequest struct {
	UserID string `json:"userId"`
}

type GetAllUserMetadataResponse struct {
	Items []MetadataItem `json:"items"`
}

type MetadataItem struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (c *client) GetAllUserMetadata(req *GetAllUserMetadataRequest) (*GetAllUserMetadataResponse, error) {
	return sendRequest(c, actionUserMetadataGet, req, func() *GetAllUserMetadataResponse {
		return &GetAllUserMetadataResponse{}
	})
}

type SetUserMetadataRequest struct {
	UserID   string         `json:"userId"`
	Metadata []MetadataItem `json:"metadata"`
}

func (c *client) SetUserMetadata(req *SetUserMetadataRequest) (*ActionStatusResponse, error) {
	return sendRequest(c, actionUserMetadataSet, req, func() *ActionStatusResponse {
		return &ActionStatusResponse{}
	})
}

type DeleteUserMetadataRequest struct {
	UserID   string   `json:"userId"`
	Metadata []string `json:"metadata"`
}

func (c *client) DeleteUserMetadata(req *DeleteUserMetadataRequest) (*ActionStatusResponse, error) {
	return sendRequest(c, actionUserMetadataDelete, req, func() *ActionStatusResponse {
		return &ActionStatusResponse{}
	})
}

type MigrateBcryptUsersRequest struct {
	Items []BcryptUserMigrationRequest `json:"items"`
}

type BcryptUserMigrationRequest struct {
	UserID       string         `json:"userId"`
	Username     string         `json:"username"`
	EmailAddress string         `json:"emailAddress"`
	PhoneNumber  string         `json:"phoneNumber,omitempty"`
	Password     BcryptPassword `json:"password"`
	Language     string         `json:"language"`
	DisableMFA   bool           `json:"disableMfa"`
}

type BcryptPassword struct {
	Algorithm string `json:"alg"`
	Hash      string `json:"hash"`
}

type MigrateUsersResponse struct {
	Items []UserID `json:"items"`
}

type UserID struct {
	UserID string `json:"userId"`
}

func (c *client) MigrateBcryptUsers(req *MigrateBcryptUsersRequest) (*MigrateUsersResponse, error) {
	return sendRequest(c, actionMigrateUsers, req, func() *MigrateUsersResponse {
		return &MigrateUsersResponse{}
	})
}

type MigrateSha512UsersRequest struct {
	Items []Sha512UserMigrationRequest `json:"items"`
}

type Sha512UserMigrationRequest struct {
	UserID       string         `json:"userId"`
	Username     string         `json:"username"`
	EmailAddress string         `json:"emailAddress"`
	PhoneNumber  string         `json:"phoneNumber,omitempty"`
	Password     Sha512Password `json:"password"`
	Language     string         `json:"language"`
	DisableMFA   bool           `json:"disableMfa"`
}

type Sha512Password struct {
	Algorithm  string `json:"alg"`
	Hash       string `json:"hash"`
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations"`
}

func (c *client) MigrateSha512Users(req *MigrateSha512UsersRequest) (*MigrateUsersResponse, error) {
	return sendRequest(c, actionMigrateUsers, req, func() *MigrateUsersResponse {
		return &MigrateUsersResponse{}
	})
}

type ImpersonateStartRequest struct {
	SessionID string `json:"sessionId"`
	UserID    string `json:"userId"`
}

type ImpersonateStartResponse struct {
	SetCookies []string `json:"setCookies"`
}

func (c *client) ImpersonateStart(req *ImpersonateStartRequest) (*ImpersonateStartResponse, error) {
	return sendRequest(c, actionImpersonateStart, req, func() *ImpersonateStartResponse {
		return &ImpersonateStartResponse{}
	})
}

type ImpersonateStopRequest struct {
	SessionID string `json:"sessionId"`
}

type ImpersonateStopResponse struct {
	SetCookies []string `json:"setCookies"`
}

func (c *client) ImpersonateStop(req *ImpersonateStopRequest) (*ImpersonateStopResponse, error) {
	return sendRequest(c, actionImpersonateStop, req, func() *ImpersonateStopResponse {
		return &ImpersonateStopResponse{}
	})
}

type CitadelAdminRequest interface {
	*CreateUserRequest |
		*GetUserRequest |
		*DeleteUserRequest |
		*UpdateUserRequest |
		*ListUsersRequest |
		*SetUserPasswordRequest |
		*ChangeUserPasswordRequest |
		*GetAllUserMetadataRequest |
		*SetUserMetadataRequest |
		*DeleteUserMetadataRequest |
		*MigrateBcryptUsersRequest |
		*MigrateSha512UsersRequest |
		*ImpersonateStartRequest |
		*ImpersonateStopRequest
}

type CitadelAdminResponse interface {
	*UserResponse |
		*ActionStatusResponse |
		*ListUsersResponse |
		*GetAllUserMetadataResponse |
		*MigrateUsersResponse |
		*ImpersonateStartResponse |
		*ImpersonateStopResponse
}

func sendRequest[RQ CitadelAdminRequest, RS CitadelAdminResponse](
	c *client,
	action string,
	req RQ,
	newRS func() RS,
) (res RS, err error) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	buf := bytes.NewBuffer(reqBody)

	resBody, err := c.request(action, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to perform action \"%s\": %w", action, err)
	}
	defer resBody.Close()

	res = newRS()
	err = json.NewDecoder(resBody).Decode(res)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return res, nil
}
