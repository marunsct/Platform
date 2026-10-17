-- Invitations (TS6): who accepted, and at most one pending invitation per address in a tenant.
ALTER TABLE invitation
    ADD COLUMN accepted_by uuid REFERENCES app_user(id),
    ADD COLUMN accepted_at timestamptz,
    ADD COLUMN sent_count  integer NOT NULL DEFAULT 0;
CREATE UNIQUE INDEX invitation_one_pending ON invitation (tenant_id, lower(email)) WHERE state = 'pending';

-- Email outbox: written in the same transaction as the change that sends it, delivered by maturad's mailer.
CREATE TABLE email_outbox (
    id              bigserial PRIMARY KEY,
    tenant_id       uuid REFERENCES tenant(id),
    to_address      text NOT NULL,
    subject         text NOT NULL,
    body_text       text NOT NULL,
    state           text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'sent', 'failed')),
    attempts        integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    sent_at         timestamptz
);
CREATE INDEX email_outbox_due ON email_outbox (next_attempt_at) WHERE state = 'pending';

-- anyone may queue mail; only operator scope (the mailer) reads or changes it
ALTER TABLE email_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY email_queue ON email_outbox FOR INSERT WITH CHECK (true);
CREATE POLICY email_operator ON email_outbox FOR ALL USING (matura_is_operator()) WITH CHECK (matura_is_operator());
