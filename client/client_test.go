package client

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseResolveSessionResponseBody_AllValid(t *testing.T) {
	body, _ := os.Open("./testdata/response-valid.json")
	res, err := parseResolveSessionResponseBody(body)

	assert.NoError(t, err, "parseResolveSessionResponseBody should not return an error")
	assert.NotNil(t, res, "parseResolveSessionResponseBody should not return a nil response")
	assert.Equal(t, "2025-04-24 09:14:29", res.ResolvedAt().Format("2006-01-02 15:04:05"), "ResolvedAt should be 2025-04-24 09:14:29")
	assert.Equal(t, "BjBVXfffI4AliYCvzaGAdQ", res.ResolutionID())
	assert.True(t, res.IsValid(), "session should be resolved as valid")

	setCookies, ok := res.SetCookies()
	assert.False(t, ok, "SetCookies should not be present")
	assert.Empty(t, setCookies, "SetCookies should be empty")

	// //////////////////
	// Session assertions
	// //////////////////
	session, ok := res.Session()
	assert.True(t, ok, "Session should be present")
	assert.NotNil(t, session, "Session should not be nil")

	assert.True(t, session.IsValid())
	sessionInvalidReason, ok := session.InvalidReason()
	assert.False(t, ok, "InvalidReason should not be present")
	assert.Empty(t, sessionInvalidReason, "InvalidReason should be empty")
	assert.Equal(t, "NOykx8JdavhLFBYzwY1epmtHfLy1anlVFuMK7-nlXh0", session.ID())
	assert.Equal(t, float64(720), session.MaxAge().Hours())
	assert.Equal(t, "2025-04-24 09:14:29", session.ResolvedAt().Format("2006-01-02 15:04:05"), "Session should have a correct resolvedAt timestamp")
	assert.Equal(t, "2025-04-09 16:38:18", session.IssuedAt().Format("2006-01-02 15:04:05"), "Session should have a correct issuedAt timestamp")
	assert.Equal(t, "2025-04-24 09:00:06", session.RefreshedAt().Format("2006-01-02 15:04:05"), "Session should have a correct refreshedAt timestamp")
	assert.Equal(t, "mNT8hkpsWOeluNtsJ5ZgByHgUmcf201rP0j9aCaEuhdVY1NSA1eQQkq2cJPBjw4kKH8-6LxdTybrOol9PdZJUA", session.DeviceID())

	sidd := session.Identities()
	assert.NotEmpty(t, sidd, "Identities should not be empty")
	assert.Len(t, sidd, 2, "Identities should have a length of 2")

	id0 := sidd[0]
	assert.Equal(t, "64d3ba00f20bfdaec54eb39e", id0.ID(), "First identity ID should match identity ID in test data")
	assert.Equal(t, "2025-04-23 18:15:10", id0.AssignedAt().Format("2006-01-02 15:04:05"), "First identity assignedAt should match identity assignedAt in test data")
	assert.IsType(t, &identity{}, id0, "First identity should be of type identity")
	assert.True(t, id0.IsImpersonated(), "First identity should be marked as impersonated")

	id1 := sidd[1]
	assert.Equal(t, "64d3aef660fd5010c3be3956", id1.ID(), "Second identity ID should match identity ID in test data")
	assert.Equal(t, "2025-04-09 16:38:18", id1.AssignedAt().Format("2006-01-02 15:04:05"), "Second identity assignedAt should match identity assignedAt in test data")
	assert.IsType(t, &identity{}, id0, "Second identity should be of type identity")
	assert.False(t, id1.IsImpersonated(), "Second identity should not be marked as impersonated")

	// ////////////////////////
	// Session token assertions
	// ////////////////////////
	token, ok := res.SessionToken()
	assert.True(t, ok, "SessionToken should be present")
	assert.NotNil(t, token, "SessionToken should not be nil")
	assert.True(t, token.IsValid(), "SessionToken should be valid")
	assert.Equal(t, "74RVs2Ok6nCwWVh0GU3VBn3rfqefB3NJ-qvQos-qzwU", token.ID(), "SessionToken ID should match ID in test data")
	tokenInvalidReason, ok := token.InvalidReason()
	assert.False(t, ok, "InvalidReason should not be present")
	assert.Empty(t, tokenInvalidReason, "InvalidReason should be empty")
	assert.Equal(t, "2025-04-24 09:14:29", token.ResolvedAt().Format("2006-01-02 15:04:05"), "SessionToken should have a correct resolvedAt timestamp")
	assert.Equal(t, "2025-04-23 18:13:07", token.IssuedAt().Format("2006-01-02 15:04:05"), "SessionToken should have a correct issuedAt timestamp")
	assert.Equal(t, float64(720), token.MaxAge().Hours())
	assert.Equal(t, "roxhill.adminv2", token.Audience(), "SessionToken audience should match audience in test data")
	assert.Equal(t, "NOykx8JdavhLFBYzwY1epmtHfLy1anlVFuMK7-nlXh0", token.SID(), "SessionToken session ID should match session ID in test data")
	assert.Equal(t, session.ID(), token.SID(), "SessionToken session ID should match session ID in test data")
	assert.Equal(t, float64(24), token.ReplaceAfter().Hours(), "SessionToken replaceAfter should match replaceAfter in test data")
	assert.Equal(t, float64(10), token.ValidAfterReplacementFor().Minutes(), "SessionToken validAfterReplacementFor should match validAfterReplacementFor in test data")

	// //////////////////////////
	// Persistent data assertions
	// //////////////////////////
	persistentData, ok := res.PersistentData()
	assert.True(t, ok, "PersistentData should be present")
	assert.NotNil(t, persistentData, "PersistentData should not be nil")
	assert.Len(t, persistentData, 2, "PersistentData should have a length of 2")

	ds0, ok := persistentData[0].Data()
	assert.True(t, ok, "Persistent data 0 should be present")
	assert.Equal(t, "64d3ba00f20bfdaec54eb39e", persistentData[0].IdentityID(), "First persistent data set's identity ID should match the first identity ID in test data")
	expectedData0 := map[string]interface{}{
		"customer_id":        "64ba9b8212efe3472ddb16f5",
		"firstname":          "Jane",
		"lastname":           "Doe",
		"legacy_customer_id": "1",
		"legacy_id":          "222222",
		"roles":              "[\"CUSTOMER_USER\",\"CUSTOMER_ADMIN\",\"USER\",\"analyticsCustomer\",\"USER_ADMIN\"]",
		"status":             "active",
	}
	for k, v := range expectedData0 {
		assert.Equal(t, v, ds0[k], "Persistent data %d: %s should match %s", 0, k, v)
	}

	ds1, ok := persistentData[1].Data()
	assert.True(t, ok, "Persistent data 1 should be present")
	assert.Equal(t, "64d3aef660fd5010c3be3956", persistentData[1].IdentityID(), "Second persistent data set's identity ID should match the first identity ID in test data")
	expectedData1 := map[string]interface{}{
		"customer_id":        "64ba9b8212efe3472ddb16f5",
		"firstname":          "John",
		"lastname":           "Smith",
		"legacy_customer_id": "2",
		"legacy_id":          "111111",
		"roles":              "[\"PLATFORM_SUPER_ADMIN\",\"PLATFORM_ADMIN\",\"CUSTOMER_USER\",\"CUSTOMER_ADMIN\",\"USER\",\"analyticsCustomer\",\"monitoringCustomer\",\"SUPER_ADMIN\",\"ADMIN\",\"USER_ADMIN\"]",
		"status":             "active",
	}
	for k, v := range expectedData1 {
		assert.Equal(t, v, ds1[k], "Persistent data %d: %s should match %s", 0, k, v)
	}
}

func TestParseResolveSessionResponseBody_InvalidSessionToken(t *testing.T) {
	body, _ := os.Open("./testdata/response-invalid-session-token.json")
	res, err := parseResolveSessionResponseBody(body)

	assert.NoError(t, err, "parseResolveSessionResponseBody should not return an error")
	assert.NotNil(t, res, "parseResolveSessionResponseBody should not return a nil response")
	assert.Equal(t, "2025-04-24 09:14:29", res.ResolvedAt().Format("2006-01-02 15:04:05"), "ResolvedAt should be 2025-04-24 09:14:29")
	assert.Equal(t, "BjBVXfffI4AliYCvzaGAdQ", res.ResolutionID())
	assert.False(t, res.IsValid(), "session should be resolved as invalid")

	setCookies, ok := res.SetCookies()
	assert.False(t, ok, "SetCookies should not be present")
	assert.Empty(t, setCookies, "SetCookies should be empty")

	// //////////////////
	// Session assertions
	// //////////////////
	session, ok := res.Session()
	assert.True(t, ok, "Session should be present")
	assert.NotNil(t, session, "Session should not be nil")

	assert.True(t, session.IsValid())
	sessionInvalidReason, ok := session.InvalidReason()
	assert.False(t, ok, "InvalidReason should not be present")
	assert.Empty(t, sessionInvalidReason, "InvalidReason should be empty")
	assert.Equal(t, "NOykx8JdavhLFBYzwY1epmtHfLy1anlVFuMK7-nlXh0", session.ID())
	assert.Equal(t, float64(720), session.MaxAge().Hours())
	assert.Equal(t, "2025-04-24 09:14:29", session.ResolvedAt().Format("2006-01-02 15:04:05"), "Session should have a correct resolvedAt timestamp")
	assert.Equal(t, "2025-04-09 16:38:18", session.IssuedAt().Format("2006-01-02 15:04:05"), "Session should have a correct issuedAt timestamp")
	assert.Equal(t, "2025-04-24 09:00:06", session.RefreshedAt().Format("2006-01-02 15:04:05"), "Session should have a correct refreshedAt timestamp")
	assert.Equal(t, "mNT8hkpsWOeluNtsJ5ZgByHgUmcf201rP0j9aCaEuhdVY1NSA1eQQkq2cJPBjw4kKH8-6LxdTybrOol9PdZJUA", session.DeviceID())

	sidd := session.Identities()
	assert.NotEmpty(t, sidd, "Identities should not be empty")
	assert.Len(t, sidd, 2, "Identities should have a length of 2")

	id0 := sidd[0]
	assert.Equal(t, "64d3ba00f20bfdaec54eb39e", id0.ID(), "First identity ID should match identity ID in test data")
	assert.Equal(t, "2025-04-23 18:15:10", id0.AssignedAt().Format("2006-01-02 15:04:05"), "First identity assignedAt should match identity assignedAt in test data")
	assert.IsType(t, &identity{}, id0, "First identity should be of type identity")
	assert.True(t, id0.IsImpersonated(), "First identity should be marked as impersonated")

	id1 := sidd[1]
	assert.Equal(t, "64d3aef660fd5010c3be3956", id1.ID(), "Second identity ID should match identity ID in test data")
	assert.Equal(t, "2025-04-09 16:38:18", id1.AssignedAt().Format("2006-01-02 15:04:05"), "Second identity assignedAt should match identity assignedAt in test data")
	assert.IsType(t, &identity{}, id0, "Second identity should be of type identity")
	assert.False(t, id1.IsImpersonated(), "Second identity should not be marked as impersonated")

	// ////////////////////////
	// Session token assertions
	// ////////////////////////
	token, ok := res.SessionToken()
	assert.True(t, ok, "SessionToken should be present")
	assert.NotNil(t, token, "SessionToken should not be nil")
	assert.False(t, token.IsValid(), "SessionToken should be invalid")
	assert.Equal(t, "VfSECxEqBxE8xKoXeOt3rRX2mSrXcSJUCjkgWK_suvQ", token.ID(), "SessionToken ID should match ID in test data")
	tokenInvalidReason, ok := token.InvalidReason()
	assert.True(t, ok, "InvalidReason should be present")
	assert.Equal(t, SessionTokenInvalidReasonReplaced, tokenInvalidReason, "InvalidReason should match invalid_replaced")
	assert.Equal(t, "2025-04-24 09:14:29", token.ResolvedAt().Format("2006-01-02 15:04:05"), "SessionToken should have a correct resolvedAt timestamp")
	assert.Equal(t, "2025-04-23 18:13:07", token.IssuedAt().Format("2006-01-02 15:04:05"), "SessionToken should have a correct issuedAt timestamp")
	assert.Equal(t, float64(720), token.MaxAge().Hours())
	assert.Equal(t, "roxhill.adminv2", token.Audience(), "SessionToken audience should match audience in test data")
	assert.Equal(t, "NOykx8JdavhLFBYzwY1epmtHfLy1anlVFuMK7-nlXh0", token.SID(), "SessionToken session ID should match session ID in test data")
	assert.Equal(t, session.ID(), token.SID(), "SessionToken session ID should match session ID in test data")
	assert.Equal(t, float64(24), token.ReplaceAfter().Hours(), "SessionToken replaceAfter should match replaceAfter in test data")
	assert.Equal(t, float64(10), token.ValidAfterReplacementFor().Minutes(), "SessionToken validAfterReplacementFor should match validAfterReplacementFor in test data")
	replaced, ok := token.Replaced()
	assert.True(t, ok, "Replaced token should be present")
	assert.Equal(t, "2025-04-23 18:13:07", replaced.At().Format("2006-01-02 15:04:05"), "Replaced token should have a correct replacedAt timestamp")
	assert.Equal(t, "74RVs2Ok6nCwWVh0GU3VBn3rfqefB3NJ-qvQos-qzwU", replaced.ID(), "Replaced token ID should match ID in test data")
}
