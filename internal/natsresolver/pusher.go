// Package natsresolver implements the "push the signed account claim to the
// running nats-server" half of NATS operator-mode credential issuance.
//
// # Why this package exists
//
// common/queueprovider/nats mints a per-tenant account NKey, signs an account
// JWT with the operator seed, and then signs a user JWT inside that account.
// None of that reaches the running nats-server on its own: the server only
// learns an account exists when the signed account claim is published to
// $SYS.REQ.CLAIMS.UPDATE by a connection authenticated into the SYSTEM
// account. common/queueprovider/nats abstracts that step behind its
// ResolverPusher interface and defaults it to a no-op, so before this package
// existed every /queue/new credential was cryptographically valid and
// operationally dead — nats-server answered the tenant's CONNECT with
// "Authorization Violation" because it had never heard of the account.
//
// Pusher is that missing implementation. It holds ONE long-lived SYS-account
// connection (established at api boot, auto-reconnecting) and does a bounded
// request/reply per claim, because it is called synchronously on the
// /queue/new request path (CLAUDE.md rule 2 — provisioning is synchronous, a
// backend failure is a 503 and never a half-issued credential).
//
// # Failure semantics
//
// Every error returned by this package wraps ErrPushFailed. Callers use
// errors.Is(err, ErrPushFailed) to distinguish "the isolation path is broken,
// fail the request" from softer credential-issuance problems. A non-ack reply
// from the server is an error exactly like a transport failure is: the account
// is not installed either way, so the credential must never be handed out.
//
// # Secrets
//
// Config.UserJWT and Config.UserSeed are credentials. They are never logged
// and every error string produced here is passed through redact() so a
// library error that echoed the credential back cannot leak it into logs.
package natsresolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

const (
	// ClaimsUpdateSubject is the nats-server system subject that accepts a
	// signed account JWT and installs/updates it in the account resolver.
	// Only connections in the system account may publish to it.
	ClaimsUpdateSubject = "$SYS.REQ.CLAIMS.UPDATE"

	// ConnectionName labels this connection in `nats server report
	// connections` so an operator can tell it apart from tenant traffic.
	ConnectionName = "instant-api-resolver-pusher"

	// DefaultPushTimeout bounds a single claims-update request/reply. It is
	// deliberately short: /queue/new is synchronous, so a NATS outage must
	// surface as a fast 503 rather than a hung request.
	DefaultPushTimeout = 5 * time.Second

	// DefaultDialTimeout bounds the boot-time connect attempt.
	DefaultDialTimeout = 5 * time.Second

	// reconnectWait is the pause between reconnect attempts after the
	// long-lived connection drops.
	reconnectWait = 2 * time.Second

	// reconnectForever keeps the client retrying for the life of the
	// process (nats.go treats a negative value as unlimited).
	reconnectForever = -1

	// redactedPlaceholder replaces any credential material found in an
	// error string before it reaches a log line.
	redactedPlaceholder = "[redacted]"

	// minRedactLen guards against replacing incidental short strings; real
	// JWTs and NKey seeds are far longer than this.
	minRedactLen = 8
)

// ErrPushFailed is the sentinel wrapped by every error this package returns.
// A caller seeing errors.Is(err, ErrPushFailed) knows the tenant's account
// claim did NOT reach the resolver, so any credential minted alongside it is
// dead and must not be returned to the customer.
var ErrPushFailed = errors.New("nats resolver: account claim push failed")

// Requester is the minimal slice of *nats.Conn this package needs. It exists
// so tests can drive the ack / non-ack / timeout paths without a real server.
type Requester interface {
	RequestWithContext(ctx context.Context, subj string, data []byte) (*nats.Msg, error)
	Close()
}

// connectFn is the dial seam. Production aliases nats.Connect 1:1; tests
// substitute a stub. Package-level var mirrors the test-seam convention in
// common/queueprovider/nats.
var connectFn = dialNATS

// dialNATS returns nats.Connect's result pair unchanged. Callers MUST check
// the error before touching the Requester: a failed nats.Connect yields a nil
// *nats.Conn boxed in a non-nil interface value.
func dialNATS(url string, opts ...nats.Option) (Requester, error) {
	return nats.Connect(url, opts...)
}

// Config describes the system-account connection used to push claims.
type Config struct {
	// URL is the server URL to connect to, e.g. nats://nats.instant-data.svc.cluster.local:4222.
	URL string

	// UserJWT is the SYS-account user JWT. SECRET — never logged.
	UserJWT string

	// UserSeed is the NKey seed matching UserJWT. SECRET — never logged.
	UserSeed string

	// Timeout bounds one claims-update request/reply. Zero → DefaultPushTimeout.
	Timeout time.Duration
}

// Pusher is a long-lived system-account connection that installs account
// claims in the resolver. Safe for concurrent use — *nats.Conn is.
type Pusher struct {
	conn    Requester
	timeout time.Duration
	// secrets are scrubbed out of every error string this Pusher produces.
	secrets []string
}

// New dials NATS as the system user and returns a ready Pusher. It fails
// loudly: a missing credential or an unreachable server is an error, never a
// silently degraded no-op pusher — a no-op pusher is precisely what made
// /queue/new hand out unusable credentials.
func New(cfg Config) (*Pusher, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, fmt.Errorf("%w: no NATS URL configured", ErrPushFailed)
	}
	if strings.TrimSpace(cfg.UserJWT) == "" {
		return nil, fmt.Errorf("%w: no system-account user JWT configured", ErrPushFailed)
	}
	if strings.TrimSpace(cfg.UserSeed) == "" {
		return nil, fmt.Errorf("%w: no system-account user NKey seed configured", ErrPushFailed)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultPushTimeout
	}
	conn, err := connectFn(cfg.URL, natsOptions(cfg)...)
	if err != nil {
		// %v (not %w) on the library error: it is rendered through redact
		// first so no credential can survive into the error chain.
		return nil, fmt.Errorf("%w: connect to %s as system user: %v",
			ErrPushFailed, cfg.URL, redact(err.Error(), cfg.UserJWT, cfg.UserSeed))
	}
	slog.Info("nats.resolver_pusher_connected",
		"url", cfg.URL,
		"subject", ClaimsUpdateSubject,
		"push_timeout", timeout.String())
	return &Pusher{
		conn:    conn,
		timeout: timeout,
		secrets: []string{cfg.UserJWT, cfg.UserSeed},
	}, nil
}

// natsOptions builds the connection options: named connection, SYS-account
// credentials, bounded dial, and unlimited reconnect so a NATS restart does
// not permanently break queue provisioning.
func natsOptions(cfg Config) []nats.Option {
	return []nats.Option{
		nats.Name(ConnectionName),
		nats.UserJWTAndSeed(cfg.UserJWT, cfg.UserSeed),
		nats.Timeout(DefaultDialTimeout),
		nats.MaxReconnects(reconnectForever),
		nats.ReconnectWait(reconnectWait),
		nats.DisconnectErrHandler(onDisconnect),
		nats.ReconnectHandler(onReconnect),
	}
}

// onDisconnect / onReconnect log connection-lifecycle transitions. They
// deliberately ignore the *nats.Conn argument: the only fields worth logging
// are static, and touching the connection from a callback risks a nil deref
// during shutdown.
func onDisconnect(_ *nats.Conn, err error) {
	slog.Warn("nats.resolver_pusher_disconnected",
		"connection", ConnectionName,
		"error", errString(err))
}

func onReconnect(_ *nats.Conn) {
	slog.Info("nats.resolver_pusher_reconnected", "connection", ConnectionName)
}

// PushAccountClaim publishes the signed account JWT to the resolver and
// requires a positive acknowledgement. Implements
// queueprovider/nats.ResolverPusher.
func (p *Pusher) PushAccountClaim(ctx context.Context, accountPublicKey, accountJWT string) error {
	if p == nil || p.conn == nil {
		return fmt.Errorf("%w: pusher is not initialised", ErrPushFailed)
	}
	if accountJWT == "" {
		return fmt.Errorf("%w: empty account JWT for account %s", ErrPushFailed, accountPublicKey)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	msg, err := p.conn.RequestWithContext(ctx, ClaimsUpdateSubject, []byte(accountJWT))
	if err != nil {
		return fmt.Errorf("%w: %s request for account %s: %v",
			ErrPushFailed, ClaimsUpdateSubject, accountPublicKey, p.redact(err.Error()))
	}
	return verifyAck(accountPublicKey, msg)
}

// Close tears down the long-lived connection. Safe on a nil/zero Pusher.
func (p *Pusher) Close() {
	if p == nil || p.conn == nil {
		return
	}
	p.conn.Close()
}

// claimsUpdateReply models the nats-server $SYS response envelope.
//
// nats-server's respondToUpdate() answers with
//
//	{"server":{...},"data":{"account":"A…","code":200,"message":"jwt updated"}}
//
// on success and the same envelope with code 500 + "description" on failure.
// The top-level "error" member is used by other $SYS endpoints; it is parsed
// too so a server-version difference surfaces as a rejection rather than
// being mistaken for an ack.
type claimsUpdateReply struct {
	Data  *claimsUpdateData  `json:"data"`
	Error *claimsUpdateError `json:"error"`
}

type claimsUpdateData struct {
	Account     string `json:"account"`
	Code        int    `json:"code"`
	Message     string `json:"message"`
	Description string `json:"description"`
}

type claimsUpdateError struct {
	Code        int    `json:"code"`
	Description string `json:"description"`
}

// verifyAck turns the resolver reply into an error unless it is an
// unambiguous success. Anything unrecognised is treated as a rejection: a
// claim that may not have been installed must never be reported as installed.
func verifyAck(accountPublicKey string, msg *nats.Msg) error {
	if msg == nil || len(msg.Data) == 0 {
		return fmt.Errorf("%w: empty reply from resolver for account %s",
			ErrPushFailed, accountPublicKey)
	}
	var reply claimsUpdateReply
	if err := json.Unmarshal(msg.Data, &reply); err != nil {
		return fmt.Errorf("%w: unparseable resolver reply for account %s: %v",
			ErrPushFailed, accountPublicKey, err)
	}
	if reply.Error != nil {
		return fmt.Errorf("%w: resolver returned an error for account %s: code=%d %s",
			ErrPushFailed, accountPublicKey, reply.Error.Code, reply.Error.Description)
	}
	if reply.Data == nil {
		return fmt.Errorf("%w: resolver reply for account %s carried no data envelope",
			ErrPushFailed, accountPublicKey)
	}
	if reply.Data.Code < http.StatusOK || reply.Data.Code >= http.StatusMultipleChoices {
		return fmt.Errorf("%w: resolver did not ack account %s: code=%d %s",
			ErrPushFailed, accountPublicKey, reply.Data.Code, ackDetail(reply.Data))
	}
	// A reply naming a different account means we cannot claim THIS account
	// was installed.
	if reply.Data.Account != "" && reply.Data.Account != accountPublicKey {
		return fmt.Errorf("%w: resolver acked a different account (want %s, got %s)",
			ErrPushFailed, accountPublicKey, reply.Data.Account)
	}
	return nil
}

// ackDetail picks whichever human-readable field the server populated.
func ackDetail(d *claimsUpdateData) string {
	if d.Description != "" {
		return d.Description
	}
	return d.Message
}

// redact scrubs this Pusher's credentials out of a string bound for a log or
// an error.
func (p *Pusher) redact(s string) string {
	return redact(s, p.secrets...)
}

func redact(s string, secrets ...string) string {
	for _, secret := range secrets {
		if len(secret) < minRedactLen {
			continue
		}
		s = strings.ReplaceAll(s, secret, redactedPlaceholder)
	}
	return s
}

// errString renders an error for a log field without a nil check at every
// call site.
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
