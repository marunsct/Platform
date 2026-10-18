-- Temporary-password invitations (TS6, technical specification §5.1): maturad creates the account at the identity
-- provider with a one-time password; the invitation remembers it and is accepted at that account's first sign-in.
ALTER TABLE invitation ADD COLUMN account_id uuid;
CREATE INDEX invitation_account ON invitation (account_id) WHERE account_id IS NOT NULL AND state = 'pending';
