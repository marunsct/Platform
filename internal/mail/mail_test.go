package mail

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
)

// fakeSMTP accepts one message and returns what the client sent.
func fakeSMTP(t *testing.T) (addr string, got <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	out := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r, w := bufio.NewReader(conn), bufio.NewWriter(conn)
		say := func(s string) { w.WriteString(s + "\r\n"); w.Flush() } //nolint:errcheck
		say("220 fake ESMTP")
		var data strings.Builder
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if line == ".\r\n" {
					inData = false
					say("250 queued")
					continue
				}
				data.WriteString(line)
				continue
			}
			switch cmd := strings.ToUpper(strings.Fields(line)[0]); cmd {
			case "EHLO", "HELO", "MAIL", "RCPT", "RSET", "NOOP":
				say("250 ok")
			case "DATA":
				inData = true
				say("354 go ahead")
			case "QUIT":
				say("221 bye")
				out <- data.String()
				return
			default:
				say("502 not implemented")
			}
		}
	}()
	return ln.Addr().String(), out
}

func TestSMTPSend(t *testing.T) {
	addr, got := fakeSMTP(t)
	s := SMTP{Addr: addr, From: "no-reply@matura.test"}
	if err := s.Send(context.Background(), "bob@example.test", "Alice invited you to Acme", "Hello,\nAccept: https://x/?token=abc\n"); err != nil {
		t.Fatal(err)
	}
	msg := <-got
	for _, want := range []string{"From: no-reply@matura.test\r\n", "To: bob@example.test\r\n",
		"Subject: Alice invited you to Acme\r\n", "Content-Type: text/plain; charset=utf-8\r\n",
		"Message-ID: <", "@matura.test>\r\n", "\r\n\r\nHello,\r\nAccept: https://x/?token=abc\r\n"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q:\n%s", want, msg)
		}
	}
}

func TestSMTPRefusesHeaderInjection(t *testing.T) {
	s := SMTP{Addr: "127.0.0.1:1", From: "no-reply@matura.test"}
	if err := s.Send(context.Background(), "bob@example.test\r\nBcc: eve@example.test", "hi", "x"); err == nil {
		t.Fatal("a recipient with a line break was accepted")
	}
}
