// Package mail delivers the email outbox (technical specification §5, TS6) over SMTP.
package mail

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/marunsct/Platform/internal/ids"
	"github.com/marunsct/Platform/internal/store"
)

const mailerLock = 7351005

// Sender delivers one message.
type Sender interface {
	Send(ctx context.Context, to, subject, body string) error
}

// SMTP sends through a relay such as Mailpit in development or the organisation's mail server. It upgrades to
// TLS when the server offers STARTTLS; credentials are only sent over TLS (or to localhost), as net/smtp enforces.
type SMTP struct {
	Addr     string // host:port
	From     string
	User     string
	Password string
}

func (s SMTP) Send(_ context.Context, to, subject, body string) error {
	if strings.ContainsAny(to, "\r\n") || strings.ContainsAny(subject, "\r\n") {
		return fmt.Errorf("refusing a header with a line break")
	}
	var auth smtp.Auth
	if s.User != "" {
		host, _, _ := net.SplitHostPort(s.Addr)
		auth = smtp.PlainAuth("", s.User, s.Password, host)
	}
	domain := s.From[strings.LastIndexByte(s.From, '@')+1:]
	msg := "From: " + s.From + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\r\n" +
		"Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n" +
		"Message-ID: <" + ids.New().String() + "@" + domain + ">\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: 8bit\r\n\r\n" +
		strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n")
	return smtp.SendMail(s.Addr, auth, s.From, []string{to}, []byte(msg))
}

// Mailer works through the email outbox. Every maturad replica runs one; an advisory lock makes one active.
type Mailer struct {
	Store    *store.Store
	Sender   Sender
	Log      *slog.Logger
	Interval time.Duration // between rounds; default 2 s
}

func (m *Mailer) defaults() {
	if m.Interval == 0 {
		m.Interval = 2 * time.Second
	}
	if m.Log == nil {
		m.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
}

// Run loops until ctx ends, taking over when the active replica goes away.
func (m *Mailer) Run(ctx context.Context) {
	m.defaults()
	for ctx.Err() == nil {
		release, ok, err := m.Store.TryLeader(ctx, mailerLock)
		if err != nil && ctx.Err() == nil {
			m.Log.Warn("mailer: leader check failed", "err", err)
		}
		if ok {
			for ctx.Err() == nil {
				if _, err := m.Round(ctx); err != nil && ctx.Err() == nil {
					m.Log.Warn("mailer round failed", "err", err)
				}
				select {
				case <-ctx.Done():
				case <-time.After(m.Interval):
				}
			}
			release()
		}
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
}

// Round sends every message that is due and returns how many were sent (tests call it directly).
func (m *Mailer) Round(ctx context.Context) (int, error) {
	m.defaults()
	due, err := m.Store.DueEmails(ctx, 50)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, e := range due {
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := m.Sender.Send(sctx, e.To, e.Subject, e.Body)
		cancel()
		if err != nil {
			m.Log.Warn("email not sent", "id", e.ID, "attempt", e.Attempts+1, "err", err)
			if err := m.Store.EmailFailed(ctx, e.ID, e.Attempts, err.Error()); err != nil {
				return sent, err
			}
			continue
		}
		if err := m.Store.EmailSent(ctx, e.ID); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}
