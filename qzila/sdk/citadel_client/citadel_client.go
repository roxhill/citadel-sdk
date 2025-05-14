package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const SDKVersion = "client-2.0.0-go"

// SessionInvalidReason represents the reason why a session is invalid.
type SessionInvalidReason string

const (
	// SessionInvalidReasonExpired SessionInvalidReasonUnknown means that the entire session is expired and
	// probably needs re-authenticating.
	SessionInvalidReasonExpired SessionInvalidReason = "invalid_expired"
	// SessionInvalidReasonNotFound means that the session ID is not found in Citadel.
	SessionInvalidReasonNotFound SessionInvalidReason = "invalid_notFound"
	// SessionInvalidReasonRevoked means that the session has been revoked by triggering any of the revoke actions.
	SessionInvalidReasonRevoked SessionInvalidReason = "invalid_revoked"
)

// newSessionInvalidReason creates a new SessionInvalidReason from a string.
// Returns an error if provided r is not a known reason.
func newSessionInvalidReason(r string) (SessionInvalidReason, error) {
	switch r {
	case "invalid_expired":
		return SessionInvalidReasonExpired, nil
	case "invalid_notFound":
		return SessionInvalidReasonNotFound, nil
	case "invalid_revoked":
		return SessionInvalidReasonRevoked, nil
	default:
		return "", fmt.Errorf("unknown reason for session invalidity: %s", r)
	}
}

// SessionTokenInvalidReason represents the reason why a session token is invalid.
type SessionTokenInvalidReason string

const (
	SessionTokenInvalidReasonNotFound               SessionTokenInvalidReason = "invalid_notFound"
	SessionTokenInvalidReasonAudience               SessionTokenInvalidReason = "invalid_audience"
	SessionTokenInvalidReasonReplaced               SessionTokenInvalidReason = "invalid_replaced"
	SessionTokenInvalidReasonExpired                SessionTokenInvalidReason = "invalid_expired"
	SessionTokenInvalidReasonRequiresEncounterToken SessionTokenInvalidReason = "invalid_requiresEncounterToken"
	SessionTokenInvalidReasonBadEncounterToken      SessionTokenInvalidReason = "invalid_badEncounterToken"
)

// newSessionTokenInvalidReason creates a new SessionTokenInvalidReason from a string.
// Returns an error if provided r is not a known reason.
func newSessionTokenInvalidReason(r string) (SessionTokenInvalidReason, error) {
	switch r {
	case "invalid_notFound":
		return SessionTokenInvalidReasonNotFound, nil
	case "invalid_audience":
		return SessionTokenInvalidReasonAudience, nil
	case "invalid_replaced":
		return SessionTokenInvalidReasonReplaced, nil
	case "invalid_expired":
		return SessionTokenInvalidReasonExpired, nil
	case "invalid_requiresEncounterToken":
		return SessionTokenInvalidReasonRequiresEncounterToken, nil
	case "invalid_badEncounterToken":
		return SessionTokenInvalidReasonBadEncounterToken, nil
	default:
		return "", fmt.Errorf("uknown reason for session token invalidity: %s", r)
	}
}

const (
	// sessionResolveAction is the action to look up and resolve an active user session
	// using authentication cookies.
	sessionResolveAction = "/sessions.resolve"
	// sessionRevokeAction is the action to take to terminate an active user session
	// identified by authentication cookies.
	sessionRevokeAction = "/sessions.revoke"
	// sessionResolveBearerAction is the action take to lookup and resolve an active
	// user session using a bearer token passed in via Authorization header.
	sessionResolveBearerAction = "/sessions.bearerResolve"
	// sessionRevokeBearerAction is the action to take to terminate an active user session
	// using a bearer token passed in via Authorization header.
	sessionRevokeBearerAction = "/sessions.bearerRevoke"
)

// ResolvedIdentity represents a resolved identity in the context of a session.
type ResolvedIdentity interface {
	// ID returns a session identifier.
	ID() string
	// AssignedAt returns the timestamp of when the identity was assigned to the session.
	AssignedAt() time.Time
	// Data returns any (meta-)data associated with the identity. The most notable
	// example at the moment is the "imersonated" key, which indicates whether the
	// identity belongs to another user, and is returned in the response because
	// a client previously issued a `adminStartImpersonating` request using
	// Citadel admin client or Admin API.
	Data() ResolvedIdentityData
	// IsImpersonated is a helper method to quickly provide information on whether
	// the current identity belongs to a user being impersonated.
	// If a resolved response includes impersonated user data, it will have two
	// resolved identities, in the session, and two sets of persistent data.
	IsImpersonated() bool
}

// ResolvedIdentityData is a simple map of string key and any type value. It is
// used to hold identity (meta-)data that is returned in the resolved session response.
type ResolvedIdentityData map[string]any

// ResolvedSessionResponse represents the shape of the response body returned
// by a successful call to either the `SessionResolve` or `SessionResolveBearer`
// action.
type ResolvedSessionResponse interface {
	// ResolvedAt returns the timestamp of when the session was resolved.
	ResolvedAt() time.Time
	// ResolutionID returns the ID of the resolution lookup.
	ResolutionID() string
	// IsValid returns true if both the session and session token are valid. If
	// any of the two is marked as invalid, this method returns false.
	IsValid() bool
	// Session returns a struct representing the `session` property from the response.
	// The returned session may be either valid or invalid.
	Session() (Session, bool)
	// SessionToken returns a struct representing the `sessionToken` property from the response.
	// The returned session token may be either valid or invalid.
	SessionToken() (SessionToken, bool)
	// PersistentData returns a slice of `SessionPersistentData` objects, which
	// are meant to hold custom data assigned to an identity.
	PersistentData() ([]SessionPersistentData, bool)
	// SetCookies returns a slice of cookies that should be set in the client
	// upon receiving the response. This is useful for the client to set new
	// authentication cookies in the browser.
	SetCookies() ([]string, bool)
}

// Session represents a user session in the context of a resolved session response.
type Session interface {
	// ID returns the session identifier.
	ID() string
	// IsValid returns true if the session is valid. If the session is invalid,
	// an `InvalidReason` will provide a string representation of why the resolving
	// action deemed the session invalid.
	IsValid() bool
	// InvalidReason will return a textual representation of the reason for
	// session invalidity. As a second return value, it will return true
	// if a reason was found, and false if the session is valid.
	InvalidReason() (SessionInvalidReason, bool)
	// IssuedAt returns the timestamp of when the session was issued (created).
	IssuedAt() time.Time
	// RefreshedAt returns the timestamp of when the session was last refreshed.
	RefreshedAt() time.Time
	// ResolvedAt returns the timestamp of when the session was resolved.
	ResolvedAt() time.Time
	// RevokedAt returns the timestamp of when the session was revoked.
	RevokedAt() (time.Time, bool)
	// MaxAge returns the maximum age of the session as time.Duration.
	MaxAge() time.Duration
	// DeviceID returns the ID of the device used to create the session.
	// This value is "kind of stable" between sessions from the same device.
	DeviceID() string
	// Identities returns a slice of `ResolvedIdentity` objects, which are meant
	// to hold the identities assigned to the session.
	Identities() []ResolvedIdentity
}

// SessionToken represents a session token in the context of a resolved session response.
type SessionToken interface {
	// ID returns the session token identifier.
	ID() string
	// IsValid returns true if the session token is valid. If the session token
	// is invalid, an `InvalidReason` will provide a string representation
	// of why the resolving action deemed the session token invalid.
	IsValid() bool
	// InvalidReason returns a textual representation of the reason for invalidity.
	// As a second return value, it will return true if a reason was found,
	// and false if the session token is valid.
	InvalidReason() (SessionTokenInvalidReason, bool)
	// EncounterToken returns an optional encounter token.
	// Use this value to track the user's encounter within the application. For
	// example, this value can be stored in the JS memory to force clients to
	// visit the identity provider every time they close the tab, but still be
	// able to identify the user.
	EncounterToken() (string, bool)
	// Audience returns the ID of an audience that the session token is valid for.
	// An audience is essentially client key pointing at a user pool in a realm.
	Audience() string
	// SID returns the ID of the session that the session token is associated with.
	SID() string
	// ResolvedAt returns the timestamp of when the session token was resolved.
	ResolvedAt() time.Time
	// IssuedAt returns the timestamp of when the session token was issued (created).
	IssuedAt() time.Time
	// MaxAge returns the maximum age of the session token as time.Duration.
	MaxAge() time.Duration
	// ReplaceAfter returns the time after which the session token should be replaced.
	ReplaceAfter() time.Duration
	// ValidAfterReplacementFor returns the time after which the session token
	// is valid after being replaced.
	ValidAfterReplacementFor() time.Duration
	// Replaced returns a `ReplacedSessionToken` object if the session token
	// was replaced. The second return value indicates whether the session
	// token was replaced or not.
	Replaced() (ReplacedSessionToken, bool)
}

// ReplacedSessionToken represents a session token that has been replaced
// by a new one.
type ReplacedSessionToken interface {
	// ID returns the ID of the replaced session token.
	ID() string
	// At returns the timestamp of when the session token was replaced.
	At() time.Time
	// EncounterToken returns an optional encounter token.
	EncounterToken() (string, bool)
}

// SessionPersistentData represents a persistent data object that is associated
// with a session and an identity. This is where your custom user data is going
// to live.
type SessionPersistentData interface {
	// IdentityID returns the ID of the identity that the persistent data is associated with.
	// Use this value to match a set of persistent user data with an identity in
	// a resolved session: `resolvedSessionResponse.Session().Identities()`
	IdentityID() string
	Data() (map[string]any, bool)
}

// ResolvedInvalidSessionData is a placeholder for invalid session data.
type ResolvedInvalidSessionData interface{}

// Client is the interface for the Citadel API client. It is used to trigger
// actions for resolving and revoking user sessions using either cookies or
// bearer tokens.
type Client interface {
	SessionResolve(request *SessionResolveRequest) (ResolvedSessionResponse, error)
	SessionResolveRaw(request *SessionResolveRequest) ([]byte, error)
	SessionRevoke(request *SessionRevokeRequest) (RevokeResponse, error)
	SessionResolveBearer(request *SessionResolveBearerRequest) (ResolvedSessionResponse, error)
	SessionResolveBearerRaw(request *SessionResolveBearerRequest) ([]byte, error)
	SessionRevokeBearer(request *SessionRevokeBearerRequest) (RevokeResponse, error)
}

// SessionResolveRequest is the request body for the `SessionResolve` and `SessionResolveRaw` actions.
type SessionResolveRequest struct {
	CookieHeader string `json:"cookieHeader"`
}

// SessionResolveBearerRequest is the request body for the `SessionResolveBearer`
// and `SessionResolveBearerRaw` actions.
type SessionResolveBearerRequest struct {
	Token string `json:"token"`
}

// client is the implementation of the Client interface.
type client struct {
	// baseURL of Citadel API endpoint.
	baseURL string
	// client is the HTTP client used to make requests.
	client *http.Client
	// clientSecret (also known as pre-shared key) is a secret string used by
	// Citadel API to identify the client making the request.
	clientSecret string
}

// ClientConfig is the configuration struct for the Citadel API client.
type ClientConfig struct {
	// BaseURL is the base URL of the Citadel API endpoint.
	BaseURL string
	// ClientSecret is the pre-shared key used by Citadel API to identify the client
	// making the request.
	ClientSecret string
}

// NewClient creates a new Citadel API client with the provided configuration.
func NewClient(config *ClientConfig) Client {
	return &client{
		baseURL:      config.BaseURL,
		client:       &http.Client{},
		clientSecret: config.ClientSecret,
	}
}

// SessionResolve sends a request to the Citadel API to resolve a user session
// using the provided cookies.
// The request body must contain the `cookieHeader` field, which is a string
// containing the authentication cookies.
func (c *client) SessionResolve(req *SessionResolveRequest) (ResolvedSessionResponse, error) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resBody, err := c.request(sessionResolveAction, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	defer resBody.Close()

	res, err := parseResolveSessionResponseBody(resBody)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return res, nil
}

// SessionResolveRaw sends a request to the Citadel API to resolve a user session
// using the provided cookies and returns a raw response as a byte slice.
// The request body must contain the `cookieHeader` field, which is a string
// containing the authentication cookies.
func (c *client) SessionResolveRaw(req *SessionResolveRequest) ([]byte, error) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resBody, err := c.request(sessionResolveAction, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	defer resBody.Close()

	resBodyBytes, err := io.ReadAll(resBody)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	return resBodyBytes, nil
}

// RevokeResponse is the interface for the response body returned by any of the
// actions that revoke a user session.
type RevokeResponse interface {
	isRevokeResponse()
}

// SessionRevokeRequest is the request body for the `SessionRevoke` action.
type SessionRevokeRequest struct {
	CookieHeader string `json:"cookieHeader"`
}

// SessionRevokeResponse is the response body for the `SessionRevoke` action.
type SessionRevokeResponse struct {
	ResponseHeaders []string `json:"responseHeaders"`
}

func (SessionRevokeResponse) isRevokeResponse() {}

// SessionRevoke sends a request to the Citadel API to revoke a user session
// using the provided cookies.
func (c *client) SessionRevoke(req *SessionRevokeRequest) (RevokeResponse, error) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resBody, err := c.request(sessionRevokeAction, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	defer resBody.Close()

	res, err := parseRevokeSessionResponseBody(resBody)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return res, nil
}

// SessionResolveBearer sends a request to the Citadel API to resolve a user session
// using the provided bearer token.
// The request body must contain the `token` field.
func (c *client) SessionResolveBearer(req *SessionResolveBearerRequest) (ResolvedSessionResponse, error) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resBody, err := c.request(sessionResolveBearerAction, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	defer resBody.Close()

	res, err := parseResolveSessionResponseBody(resBody)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return res, nil
}

// SessionResolveBearerRaw sends a request to the Citadel API to resolve a user session
// using the provided bearer token and returns a raw response as a byte slice.
// The request body must contain the `token` field.
func (c *client) SessionResolveBearerRaw(req *SessionResolveBearerRequest) ([]byte, error) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resBody, err := c.request(sessionResolveBearerAction, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	defer resBody.Close()

	resBodyBytes, err := io.ReadAll(resBody)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	return resBodyBytes, nil
}

// SessionRevokeBearerRequest is the request body for the `SessionRevokeBearer` action.
type SessionRevokeBearerRequest struct {
	Token string `json:"token"`
}

// BearerRevokeResponse is the response body for the `SessionRevokeBearer` action.
type BearerRevokeResponse struct {
	Status string `json:"status"`
}

func (BearerRevokeResponse) isRevokeResponse() {}

// SessionRevokeBearer sends a request to the Citadel API to revoke a user session
// using the provided bearer token.
func (c *client) SessionRevokeBearer(req *SessionRevokeBearerRequest) (RevokeResponse, error) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resBody, err := c.request(sessionRevokeBearerAction, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	defer resBody.Close()

	res, err := parseRevokeSessionResponseBody(resBody)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return res, nil
}

// sessionResolveResponse is the implementation of the ResolvedSessionResponse
// interface.
// It represents the response body returned by a successful call to trigger any
// action that resolves a user session using cookies or bearer tokens.
// Please, keep in mind that any response with status code between 200 and 299
// is going to be considered a success, even if the session is invalid. You can
// perform additional session/session token validity checks using their respective
// interfaces.
type sessionResolveResponse struct {
	resolvedAt   time.Time
	resolutionID string
	session      Session
	token        SessionToken
	data         []SessionPersistentData
	setCookies   []string
}

// ResolvedAt returns the timestamp of when the session was resolved in Citadel.
func (r *sessionResolveResponse) ResolvedAt() time.Time {
	return r.resolvedAt
}

// ResolutionID returns the ID of the resolution lookup.
// Essentially it's the ID of the resolution request.
func (r *sessionResolveResponse) ResolutionID() string {
	return r.resolutionID
}

// IsValid returns true if both the session and session token are valid.
// If any of the two is marked as invalid, this method returns false.
func (r *sessionResolveResponse) IsValid() bool {
	return r.session.IsValid() && r.token.IsValid()
}

// Session returns a Session interface.
// The returned session can be either valid or invalid. If the underlying session
// is invalid, it will provide a reason for invalidity in the session.InvalidReason()
// method.
func (r *sessionResolveResponse) Session() (Session, bool) {
	if r.session != nil {
		return r.session, true
	}
	return nil, false
}

// SessionToken returns a SessionToken interface.
// The returned session token can be either valid or invalid. If the underlying
// session token is invalid, it will provide a reason for invalidity in the
// sessionToken.InvalidReason() method.
func (r *sessionResolveResponse) SessionToken() (SessionToken, bool) {
	if r.token != nil {
		return r.token, true
	}
	return nil, false
}

// PersistentData returns a slice of `SessionPersistentData` objects, which
// are meant to hold custom data assigned to an identity.
func (r *sessionResolveResponse) PersistentData() ([]SessionPersistentData, bool) {
	if len(r.data) > 0 {
		return r.data, true
	}
	return nil, false
}

// SetCookies returns a slice of cookies that should be set in the client
// upon receiving the response.
func (r *sessionResolveResponse) SetCookies() ([]string, bool) {
	if len(r.setCookies) > 0 {
		return r.setCookies, true
	}
	return []string{}, false
}

// parseResolveSessionResponseBody parses the response body returned by the Citadel API
// and returns a ResolvedSessionResponse interface.
func parseResolveSessionResponseBody(resBody io.ReadCloser) (ResolvedSessionResponse, error) {
	var data map[string]any
	var err error

	err = json.NewDecoder(resBody).Decode(&data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	res := &sessionResolveResponse{}

	if res.resolvedAt, err = getTimeFromRFC3339(data, "resolvedAt"); err != nil {
		return nil, fmt.Errorf("resolvedAt missing or malformed in response")
	}
	if res.resolutionID, err = getString(data, "resolutionId"); err != nil {
		return nil, fmt.Errorf("resolutionId missing or malformed in response")
	}

	var itemData map[string]any
	itemData, err = getValidOrInvalidData(data)
	if err != nil {
		return nil, fmt.Errorf("session data missing or malformed in response")
	}

	// Parse session data
	var sessionData map[string]any
	if sessionData, err = getMap(itemData, "session"); err != nil {
		return nil, fmt.Errorf("session data missing or malformed in response")
	}
	res.session, err = transformSessionData(sessionData)
	if err != nil {
		return nil, fmt.Errorf("failed to transform session data: %w", err)
	}

	// Parse session token data
	var tokenData map[string]any
	if tokenData, err = getMap(itemData, "sessionToken"); err != nil {
		return nil, fmt.Errorf("session token data missing or malformed in response")
	}
	res.token, err = transformSessionTokenData(tokenData)
	if err != nil {
		return nil, fmt.Errorf("failed to transform session token data: %w", err)
	}

	// Parse persistent identity data
	var persistentData []any
	if persistentData, err = getSliceOfAny(itemData, "persistentData"); err != nil {
		return nil, fmt.Errorf("persistentData missing or malformed in response")
	}
	pds := make([]map[string]any, len(persistentData))
	for i, item := range persistentData {
		// Make sure the item is a map[string]any
		persistentDataItem, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("persistentData %d malformed in response", i)
		}
		pds[i] = persistentDataItem
	}

	res.data, err = transformSessionPersistentData(pds)
	if err != nil {
		return nil, fmt.Errorf("failed to transform session persistent data: %w", err)
	}

	return res, nil
}

// session is the implementation of the Session interface.
type session struct {
	id            string
	isValid       bool
	issuedAt      time.Time
	refreshedAt   time.Time
	resolvedAt    time.Time
	revokedAt     time.Time
	deviceID      string
	identities    []ResolvedIdentity
	maxAge        time.Duration
	invalidReason SessionInvalidReason
}

// ID returns the session identifier.
func (s *session) ID() string {
	return s.id
}

// IsValid returns true if the session is valid, false otherwise.
func (s *session) IsValid() bool {
	return s.isValid
}

// IssuedAt returns the timestamp of when the session was issued (created).
func (s *session) IssuedAt() time.Time {
	return s.issuedAt
}

// RefreshedAt returns the timestamp of when the session was last refreshed.
func (s *session) RefreshedAt() time.Time {
	return s.refreshedAt
}

// ResolvedAt returns the timestamp of when the session was resolved (looked up in Citadel)
func (s *session) ResolvedAt() time.Time {
	return s.resolvedAt
}

func (s *session) RevokedAt() (time.Time, bool) {
	if !s.revokedAt.IsZero() && s.invalidReason == SessionInvalidReasonRevoked {
		return s.revokedAt, true
	}
	return time.Time{}, false
}

// DeviceID returns the unique identifier of the device used to create the session.
// Semi-stable.
func (s *session) DeviceID() string {
	return s.deviceID
}

// Identities returns a slice of `ResolvedIdentity` objects, which are meant
// to hold the identities assigned to the session.
func (s *session) Identities() []ResolvedIdentity {
	return s.identities
}

// InvalidReason returns a textual representation of the reason for session invalidity.
func (s *session) InvalidReason() (SessionInvalidReason, bool) {
	if s.invalidReason != "" {
		return s.invalidReason, true
	}
	return "", false
}

// MaxAge returns the maximum age of the session as time.Duration.
func (s *session) MaxAge() time.Duration {
	return s.maxAge
}

// identity is the implementation of the ResolvedIdentity interface.
type identity struct {
	id         string
	assignedAt time.Time
	data       map[string]any
}

// ID returns the unique identifier of a session identity.
func (i *identity) ID() string {
	return i.id
}

// AssignedAt returns the timestamp of when the identity was assigned to the session.
func (i *identity) AssignedAt() time.Time {
	return i.assignedAt
}

// Data returns any (meta-)data associated with the identity.
func (i *identity) Data() ResolvedIdentityData {
	return i.data
}

// IsImpersonated is a helper method to quickly provide information on whether
// the current identity belongs to a user being impersonated.
func (i *identity) IsImpersonated() bool {
	if isImpersonated, ok := i.data["impersonated"].(bool); ok {
		return isImpersonated
	}
	return false
}

// transformSessionData turns the raw session data into a Session interface.
func transformSessionData(data map[string]any) (Session, error) {
	var err error
	s := new(session)

	if s.isValid, err = getBool(data, "isValid"); err != nil {
		return nil, fmt.Errorf("session validity missing or invalid in response")
	}
	// An invalid session must have an "invalidReason" key.
	if !s.isValid {
		reason, err := getString(data, "reason")
		if err != nil {
			return nil, fmt.Errorf("session invalid reason missing or malformed in response")
		}
		s.invalidReason, err = newSessionInvalidReason(reason)
		if err != nil {
			return nil, err
		}
		if s.invalidReason == SessionInvalidReasonRevoked {
			s.revokedAt, err = getTimeFromRFC3339(data, "revokedAt")
		}
	}
	if s.resolvedAt, err = getTimeFromRFC3339(data, "resolvedAt"); err != nil {
		return nil, fmt.Errorf("resolvedAt missing or invalid in response")
	}

	// Actual session data reside under either "valid" or "invalid" key.
	sd, err := getValidOrInvalidData(data)
	if err != nil {
		return nil, fmt.Errorf("session data missing or malformed in response")
	}

	if s.id, err = getString(sd, "id"); err != nil {
		return nil, fmt.Errorf("session ID missing or malformed in response")
	}
	if s.issuedAt, err = getTimeFromRFC3339(sd, "issuedAt"); err != nil {
		return nil, fmt.Errorf("issuedAt missing or malformed in response")
	}
	if s.refreshedAt, err = getTimeFromRFC3339(sd, "refreshedAt"); err != nil {
		return nil, fmt.Errorf("refreshedAt missing or malformed in response")
	}
	if s.maxAge, err = getDuration(sd, "maxAge"); err != nil {
		return nil, fmt.Errorf("maxAge missing or malformed in response")
	}
	if s.deviceID, err = getString(sd, "deviceId"); err != nil {
		return nil, fmt.Errorf("deviceId missing or malformed in response")
	}

	if identities, err := getSliceOfAny(sd, "identities"); err != nil {
		return nil, fmt.Errorf("identities missing in response")
	} else {
		for i, item := range identities {
			// Assert that the item is a map[string]any
			identityData, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("identity %d malformed in response", i)
			}

			_identity := identity{}
			if _identity.id, err = getString(identityData, "id"); err != nil {
				return nil, fmt.Errorf("identity %d ID missing in response", i)
			}
			if _identity.assignedAt, err = getTimeFromRFC3339(identityData, "assignedAt"); err != nil {
				return nil, fmt.Errorf("identity %d assignedAt missing in response", i)
			}
			// Special case: don't fail if identity data is not defined, just set it to
			// an empty map.
			if _identity.data, err = getMap(identityData, "data"); err != nil {
				_identity.data = map[string]any{}
			}

			s.identities = append(s.identities, &_identity)
		}
	}

	return s, nil
}

// sessionToken is the implementation of the SessionToken interface.
type sessionToken struct {
	id                       string
	isValid                  bool
	invalidReason            SessionTokenInvalidReason
	resolvedAt               time.Time
	audience                 string
	sessionID                string
	issuedAt                 time.Time
	maxAge                   time.Duration
	replaceAfter             time.Duration
	validAfterReplacementFor time.Duration
	encounterToken           string
	replaced                 ReplacedSessionToken
}

// ID returns the unique session token identifier.
func (st *sessionToken) ID() string {
	return st.id
}

// IsValid returns true if the session token is valid, false otherwise.
func (st *sessionToken) IsValid() bool {
	return st.isValid
}

// InvalidReason returns a textual representation of the reason for session token invalidity.
func (st *sessionToken) InvalidReason() (SessionTokenInvalidReason, bool) {
	if st.invalidReason != "" {
		return st.invalidReason, true
	}
	return "", false
}

// EncounterToken returns an optional encounter token that can be used to track
// the user's interactions with the application.
func (st *sessionToken) EncounterToken() (string, bool) {
	if st.sessionID == "" {
		return "", false
	}
	return st.sessionID, true
}

// Audience returns the ID of an audience that the session token is valid for.
func (st *sessionToken) Audience() string {
	return st.audience
}

// SID returns the ID of the session that the session token is associated with.
func (st *sessionToken) SID() string {
	return st.sessionID
}

// ResolvedAt returns the timestamp of when the session token was resolved (looked up in Citadel).
func (st *sessionToken) ResolvedAt() time.Time {
	return st.resolvedAt
}

// IssuedAt returns the timestamp of when the session token was issued (created).
func (st *sessionToken) IssuedAt() time.Time {
	return st.issuedAt
}

// MaxAge returns the maximum age of the session token as time.Duration.
func (st *sessionToken) MaxAge() time.Duration {
	return st.maxAge
}

// ReplaceAfter returns the time after which the session token should be replaced.
func (st *sessionToken) ReplaceAfter() time.Duration {
	return st.replaceAfter
}

// ValidAfterReplacementFor returns the time after which the session token remains
// valid after being replaced.
func (st *sessionToken) ValidAfterReplacementFor() time.Duration {
	return st.validAfterReplacementFor
}

// Replaced returns a `ReplacedSessionToken` object if the session token was replaced.
func (st *sessionToken) Replaced() (ReplacedSessionToken, bool) {
	if st.replaced == nil {
		return nil, false
	}
	return st.replaced, true
}

// ReplacedSessionToken is the implementation of the ReplacedSessionToken interface.
type replacedSessionToken struct {
	id             string
	replacedAt     time.Time
	encounterToken string
}

// ID returns the unique identifier of the replaced session token.
func (rst *replacedSessionToken) ID() string {
	return rst.id
}

// At returns the timestamp of when the session token was replaced.
func (rst *replacedSessionToken) At() time.Time {
	return rst.replacedAt
}

// EncounterToken returns an optional encounter token that can be used to track
// the user's interactions with the application.
func (rst *replacedSessionToken) EncounterToken() (string, bool) {
	if rst.encounterToken == "" {
		return "", false
	}
	return rst.encounterToken, true
}

// transformSessionTokenData turns the raw session token data into a SessionToken interface.
func transformSessionTokenData(data map[string]any) (SessionToken, error) {
	var err error
	st := new(sessionToken)

	if st.isValid, err = getBool(data, "isValid"); err != nil {
		return nil, fmt.Errorf("session token validity missing or invalid in response")
	}
	if !st.isValid {
		reason, err := getString(data, "reason")
		if err != nil {
			return nil, fmt.Errorf("session token invalidity reason missing or malformed in response")
		}
		st.invalidReason, err = newSessionTokenInvalidReason(reason)
		if err != nil {
			return nil, err
		}
	}
	if st.resolvedAt, err = getTimeFromRFC3339(data, "resolvedAt"); err != nil {
		return nil, fmt.Errorf("resolvedAt missing or malformed in response")
	}

	var tokenData map[string]any

	if tokenData, err = getValidOrInvalidData(data); err != nil {
		return nil, fmt.Errorf("session token data missing or malformed in response")
	}
	if st.id, err = getString(tokenData, "id"); err != nil {
		return nil, fmt.Errorf("session token's ID missing in response")
	}
	if st.audience, err = getString(tokenData, "audience"); err != nil {
		return nil, fmt.Errorf("session token's audience missing in response")
	}
	if st.sessionID, err = getString(tokenData, "sessionId"); err != nil {
		return nil, fmt.Errorf("session token's session ID missing in response")
	}
	if st.issuedAt, err = getTimeFromRFC3339(tokenData, "issuedAt"); err != nil {
		return nil, fmt.Errorf("session token's issuedAt missing or malformed in response")
	}
	if st.maxAge, err = getDuration(tokenData, "maxAge"); err != nil {
		return nil, fmt.Errorf("session token's maxAge missing or malformed in response")
	}
	if st.replaceAfter, err = getDuration(tokenData, "replaceAfter"); err != nil {
		return nil, fmt.Errorf("session token's replaceAfter missing or malformed in response")
	}
	if st.validAfterReplacementFor, err = getDuration(tokenData, "validAfterReplacementFor"); err != nil {
		return nil, fmt.Errorf("session token's validAfterReplacementFor missing or malformed in response")
	}

	if replaced, err := getMap(tokenData, "replaced"); err == nil {
		r := replacedSessionToken{}

		if r.id, err = getString(replaced, "id"); err != nil {
			return nil, fmt.Errorf("session token's replaced session token ID missing in response")
		}
		if r.replacedAt, err = getTimeFromRFC3339(replaced, "at"); err != nil {
			return nil, fmt.Errorf("session token's replaced session token replacedAt missing or malformed in response")
		}
		// Encounter token is optional, so we don't fail if it's not present.
		r.encounterToken, _ = getString(replaced, "encounterToken")

		st.replaced = &r
	}

	return st, nil
}

// sessionPersistentData is the implementation of the SessionPersistentData interface.
type sessionPersistentData struct {
	identityID string
	data       map[string]any
}

// IdentityID returns the ID of the identity that the persistent data is associated with.
func (spd *sessionPersistentData) IdentityID() string {
	return spd.identityID
}

// Data returns the persistent data associated with the identity.
func (spd *sessionPersistentData) Data() (map[string]any, bool) {
	if len(spd.data) > 0 {
		return spd.data, true
	}
	return nil, false
}

// transformSessionPersistentData turns the raw session persistent data into a slice of
// SessionPersistentData interfaces.
func transformSessionPersistentData(data []map[string]any) ([]SessionPersistentData, error) {
	var dataItems []SessionPersistentData
	var err error

	for _, item := range data {
		datum := new(sessionPersistentData)

		if datum.identityID, err = getString(item, "identityId"); err != nil {
			return nil, fmt.Errorf("identity ID of a persistent data object missing in response")
		}
		if datum.data, err = getMap(item, "data"); err != nil {
			return nil, fmt.Errorf("data of a persistent data object missing or malformed in response")
		}

		dataItems = append(dataItems, datum)
	}

	return dataItems, nil
}

// parseRFC3339WithMillis parses a datetime string like "2025-04-24T09:14:29.541Z"
// and returns a time.Time value.
func parseRFC3339WithMillis(s string) (time.Time, error) {
	const layout = time.RFC3339Nano // Handles sub-second precision like .541Z
	t, err := time.Parse(layout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid datetime format: %w", err)
	}
	return t, nil
}

// getValidOrInvalidData returns a map of details from any map that might have
// either a "valid" or "invalid" key.
// Since both valid and invalid sessions, session tokens, and resolve session
// responses share the majority of properties, we can use this function to
// extract the data we need, and fill any additional properties using manual
// checks in individual transformer functions.
func getValidOrInvalidData(m map[string]any) (map[string]any, error) {
	if data, ok := m["valid"].(map[string]any); ok {
		return data, nil
	}
	if data, ok := m["invalid"].(map[string]any); ok {
		return data, nil
	}
	return nil, fmt.Errorf("data not found")
}

// getString retrieves a string value from a map by key.
func getString(m map[string]any, key string) (string, error) {
	val, ok := m[key]
	if !ok {
		return "", fmt.Errorf("%q missing", key)
	}
	str, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("%q is not a string", key)
	}
	return str, nil
}

// getBool retrieves a boolean value from a map by key.
func getBool(m map[string]any, key string) (bool, error) {
	val, ok := m[key]
	if !ok {
		return false, fmt.Errorf("%q missing", key)
	}
	b, ok := val.(bool)
	if !ok {
		return false, fmt.Errorf("%q is not a bool", key)
	}
	return b, nil
}

// getFloat64 retrieves a float64 value from a map by key.
func getFloat64(m map[string]any, key string) (float64, error) {
	val, ok := m[key]
	if !ok {
		return 0, fmt.Errorf("%q missing", key)
	}
	num, ok := val.(float64)
	if !ok {
		return 0, fmt.Errorf("%q is not a float64", key)
	}
	return num, nil
}

// getMap retrieves a map[string]any value from a map by key.
func getMap(m map[string]any, key string) (map[string]any, error) {
	val, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("%q missing", key)
	}
	casted, ok := val.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%q is not a map[string]any", key)
	}
	return casted, nil
}

// getTimeFromRFC3339 retrieves a timestamp in RFC3339 format (with millisecond)
// by key as a string, then parses it into a time.Time.
func getTimeFromRFC3339(m map[string]any, key string) (time.Time, error) {
	var zero time.Time

	ts, err := getString(m, key)
	if err != nil {
		return zero, fmt.Errorf("%s not set or malformed in map", key)
	}
	t, err := parseRFC3339WithMillis(ts)
	if err != nil {
		return zero, fmt.Errorf("failed to parse %q as time.Time: %w", key, err)
	}
	return t, nil
}

// getDuration retrieves a duration in seconds from a map by key and transforms
// it into a time.Duration.
func getDuration(m map[string]any, key string) (time.Duration, error) {
	df, err := getFloat64(m, key)
	if err != nil {
		return 0, fmt.Errorf("%q not set or malformed in map", key)
	}
	return time.Duration(int(df)) * time.Second, nil
}

// getSliceOfAny retrieves a slice of string key and any type value from a map
// by key.
func getSliceOfAny(m map[string]any, key string) ([]any, error) {
	val, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("%q missing", key)
	}
	arr, ok := val.([]any)
	if !ok {
		return nil, fmt.Errorf("%q is not a slice of any type", key)
	}
	return arr, nil
}

// request sends a POST request to the Citadel API with the specified action
// and body. It returns the response body or an error if the request fails.
func (c *client) request(action string, body io.Reader) (io.ReadCloser, error) {
	req, err := http.NewRequest("POST", c.baseURL+action, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-sdk-version", SDKVersion)
	req.Header.Set("Authorization", c.clientSecret)

	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	// Handle API Gateway errors
	if res.StatusCode == http.StatusInternalServerError ||
		res.StatusCode == http.StatusServiceUnavailable ||
		res.StatusCode == http.StatusGatewayTimeout ||
		res.StatusCode == http.StatusBadGateway ||
		res.StatusCode == http.StatusUnauthorized ||
		res.StatusCode == http.StatusForbidden {
		bodyBytes, err := io.ReadAll(res.Body)
		if err == nil {
			err := &UnexpectedError{
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
			return nil, &ConfigError{errorResponse.Message.Message}
		case "bearerMalformed":
			return nil, &BearerMalformedError{errorResponse.Message.Message}
		case "notFound":
			return nil, &NotFoundError{errorResponse.Message.Message}
		case "bearerExpired":
			return nil, &BearerExpiredError{errorResponse.Message.Message}
		case "sessionInvalid":
			return nil, &SessionInvalidError{errorResponse.Message.Message}
		default:
			return nil, &UnexpectedError{fmt.Sprintf("Unexpected error.\nType: %v\nMessage: %v", errorResponse.Message.Type, errorResponse.Message.Message)}
		}
	}

	return res.Body, nil
}

// UnexpectedError is a custom error type for errors we could not predict.
type UnexpectedError struct {
	Message string
}

// CitadelError is a struct that represents the error message returned by Citadel API.
type CitadelError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// ErrorResponse is a struct that represents the error response returned by Citadel API.
type ErrorResponse struct {
	Id      string       `json:"errorId,omitempty"`
	Message CitadelError `json:"error"`
}

// Error implements the error interface for UnexpectedError.
func (e *UnexpectedError) Error() string {
	return e.Message
}

// ConfigError is a custom error type for configuration errors.
type ConfigError struct {
	Message string
}

// Error implements the error interface for ConfigError.
func (e *ConfigError) Error() string {
	return e.Message
}

// BearerMalformedError is a custom error type for malformed bearer token errors.
type BearerMalformedError struct {
	Message string
}

// Error implements the error interface for BearerMalformedError.
func (e *BearerMalformedError) Error() string {
	return e.Message
}

// NotFoundError is a custom error type for not found errors.
type NotFoundError struct {
	Message string
}

// Error implements the error interface for NotFoundError.
func (e *NotFoundError) Error() string {
	return e.Message
}

// BearerExpiredError is a custom error type for expired bearer token errors.
type BearerExpiredError struct {
	Message string
}

// Error implements the error interface for BearerExpiredError.
func (e *BearerExpiredError) Error() string {
	return e.Message
}

// SessionInvalidError is a custom error type for invalid session errors.
type SessionInvalidError struct {
	Message string
}

// Error implements the error interface for SessionInvalidError.
func (e *SessionInvalidError) Error() string {
	return e.Message
}

// parseRevokeSessionResponseBody parses the response body returned by the Citadel API
// and returns a RevokeResponse interface.
func parseRevokeSessionResponseBody(rc io.ReadCloser) (RevokeResponse, error) {
	// Read the entire body
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Try to unmarshal into a generic map to inspect keys
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal to generic map: %w", err)
	}

	switch {
	case raw["responseHeaders"] != nil:
		var resp SessionRevokeResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, fmt.Errorf("failed to unmarshal as SessionRevokeResponse: %w", err)
		}
		return resp, nil

	case raw["status"] == "success":
		var resp BearerRevokeResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, fmt.Errorf("failed to unmarshal as BearerRevokeResponse: %w", err)
		}
		return resp, nil

	default:
		return nil, fmt.Errorf("unknown revoke response format")
	}
}
