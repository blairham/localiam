// SPDX-FileCopyrightText: 2026 Blair Hamilton
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/blairham/localiam/verify"
)

const (
	cacheGroup = "localiam-redis"
	cacheUser  = "localiam-iam"
)

func elastiCacheToken(t *testing.T, at time.Time) string {
	t.Helper()
	return presign(t, cacheGroup, "elasticache",
		url.Values{"Action": {"connect"}, "User": {cacheUser}}, at)
}

// TestAnExpiredTokenIsRejected is the whole reason this package exists.
//
// The bug class: a service mints one ElastiCache token at startup and reuses it
// for the life of the pod. The connection survives for hours, then drops; the
// reconnect re-auths with the long-expired token, ElastiCache answers
// WRONGPASS, and the pod stays broken for the rest of its life.
// An in-cluster broker that accepts any token cannot reproduce that. This one can.
func TestAnExpiredTokenIsRejected(t *testing.T) {
	t.Parallel()
	token := elastiCacheToken(t, frozen)

	// 900s TTL; present it 16 minutes later, exactly as a reconnect would.
	_, err := verify.ElastiCache(token, cacheGroup, cacheUser, testRegion, testStore(t), frozen.Add(16*time.Minute))
	if !errors.Is(err, verify.ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
}

// TestATokenInsideItsWindowIsAccepted is the other half of the pair: the same
// token, presented before expiry, must still work — otherwise the expiry test
// above would pass for the wrong reason.
func TestATokenInsideItsWindowIsAccepted(t *testing.T) {
	t.Parallel()
	token := elastiCacheToken(t, frozen)

	if _, err := verify.ElastiCache(
		token,
		cacheGroup,
		cacheUser,
		testRegion,
		testStore(t),
		frozen.Add(14*time.Minute),
	); err != nil {
		t.Fatalf("token 14m into a 15m window rejected: %v", err)
	}
}

func TestVerifyRejections(t *testing.T) {
	t.Parallel()

	emptyStore := verify.NewStore()
	sessionStore := verify.NewStore()
	sessionStore.Add(verify.Principal{
		AccessKeyID:  testAccessKey,
		SecretKey:    testSecretKey,
		SessionToken: "the-issued-session-token",
		ARN:          testARN,
	})

	// Tokens are minted eagerly against the parent t rather than lazily in each
	// case, so no case carries a *testing.T-taking closure. That keeps the table
	// readable and avoids the thelper lint on seven near-identical literals.
	tests := []struct {
		at    time.Time
		want  error
		store *verify.Store
		name  string
		token string
		group string
		user  string
	}{
		{
			name:  "signed too far in the future",
			token: elastiCacheToken(t, frozen.Add(10*time.Minute)),
			at:    frozen,
			want:  verify.ErrNotYetValid,
		},
		{
			name: "a signed parameter was altered after signing",
			token: strings.Replace(elastiCacheToken(t, frozen),
				"X-Amz-Expires=900", "X-Amz-Expires=9000", 1),
			want: verify.ErrBadSignature,
		},
		{
			name:  "the access key is not one localiam issued",
			token: elastiCacheToken(t, frozen),
			store: emptyStore,
			want:  verify.ErrUnknownKey,
		},
		{
			name:  "the token was minted for a different replication group",
			token: elastiCacheToken(t, frozen),
			group: "some-other-group",
			want:  verify.ErrWrongHost,
		},
		{
			name: "the token names a different ElastiCache user than AUTH did",
			token: presign(t, cacheGroup, "elasticache",
				url.Values{"Action": {"connect"}, "User": {"someone-else"}}, frozen),
			want: verify.ErrWrongAction,
		},
		{
			name: "the token is scoped to a different service",
			token: presign(t, cacheGroup, "rds-db",
				url.Values{"Action": {"connect"}, "User": {cacheUser}}, frozen),
			want: verify.ErrWrongScope,
		},
		{
			name:  "a session principal presented no session token",
			token: elastiCacheToken(t, frozen),
			store: sessionStore,
			want:  verify.ErrSessionMismatch,
		},
		{
			name: "a session principal presented another session token",
			token: presign(t, cacheGroup, "elasticache", url.Values{
				"Action": {"connect"}, "User": {cacheUser},
				"X-Amz-Security-Token": {"not-the-issued-session-token"},
			}, frozen),
			store: sessionStore,
			want:  verify.ErrSessionMismatch,
		},
		{
			name: "a session principal presented a prefix of its session token",
			token: presign(t, cacheGroup, "elasticache", url.Values{
				"Action": {"connect"}, "User": {cacheUser},
				"X-Amz-Security-Token": {"the-issued-session"},
			}, frozen),
			store: sessionStore,
			want:  verify.ErrSessionMismatch,
		},
		{
			name:  "the token carries no signature at all",
			token: cacheGroup + "/?Action=connect",
			want:  verify.ErrMalformed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			group := tc.group
			if group == "" {
				group = cacheGroup
			}
			user := tc.user
			if user == "" {
				user = cacheUser
			}
			store := tc.store
			if store == nil {
				store = testStore(t)
			}
			at := tc.at
			if at.IsZero() {
				at = frozen.Add(time.Minute)
			}

			_, err := verify.ElastiCache(tc.token, group, user, testRegion, store, at)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestMSKOAuthBearerRejectsMalformedEnvelopes(t *testing.T) {
	t.Parallel()

	// Not base64 at all.
	if _, err := verify.MSKOAuthBearer(
		"!!!not-base64!!!",
		testRegion,
		"",
		testStore(t),
		frozen,
	); !errors.Is(
		err,
		verify.ErrMalformed,
	) {
		t.Errorf("bad base64: got %v, want ErrMalformed", err)
	}

	// Valid base64, but the decoded bytes are not a presigned URL.
	junk := base64.RawURLEncoding.EncodeToString([]byte("hello"))
	if _, err := verify.MSKOAuthBearer(junk, testRegion, "", testStore(t), frozen); !errors.Is(err, verify.ErrMalformed) {
		t.Errorf("junk payload: got %v, want ErrMalformed", err)
	}
}

func TestMSKAWSMSKIAMRejectsAnUnknownField(t *testing.T) {
	t.Parallel()
	// An unrecognized field must be a hard error, never silently dropped: a
	// dropped field is one the signature covered but the verifier did not, which
	// is a signature bypass.
	payload := []byte(`{"version":"2020_10_22","host":"kafka.us-east-1.amazonaws.com",` +
		`"x-amz-signature":"00","surprise":"value"}`)
	if _, err := verify.MSKAWSMSKIAM(payload, testRegion, "", testStore(t), frozen); !errors.Is(err, verify.ErrMalformed) {
		t.Errorf("got %v, want ErrMalformed", err)
	}
}

// TestASessionPrincipalAcceptsItsOwnSessionToken is the positive half of the
// session-mismatch rejections: the token the STS shim issued still verifies.
func TestASessionPrincipalAcceptsItsOwnSessionToken(t *testing.T) {
	t.Parallel()
	store := verify.NewStore()
	store.Add(verify.Principal{
		AccessKeyID:  testAccessKey,
		SecretKey:    testSecretKey,
		SessionToken: "the-issued-session-token",
		ARN:          testARN,
	})
	token := presign(t, cacheGroup, "elasticache", url.Values{
		"Action": {"connect"}, "User": {cacheUser},
		"X-Amz-Security-Token": {"the-issued-session-token"},
	}, frozen)

	if _, err := verify.ElastiCache(token, cacheGroup, cacheUser, testRegion, store, frozen.Add(time.Minute)); err != nil {
		t.Fatalf("the issued session token was rejected: %v", err)
	}
}
