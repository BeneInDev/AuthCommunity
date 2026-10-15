-- Local preparation only. Apply once, in order, using a trusted migration owner.
BEGIN;
CREATE SCHEMA IF NOT EXISTS private;

CREATE TABLE private.oauth_authorizations (
    id uuid PRIMARY KEY,
    discord_id text NOT NULL CHECK (discord_id ~ '^[0-9]{17,20}$'),
    client_id text NOT NULL CHECK (client_id ~ '^[0-9]{17,20}$'),
    envelope jsonb,
    access_expires_at timestamptz NOT NULL,
    scopes text[] NOT NULL CHECK (cardinality(scopes) BETWEEN 1 AND 32 AND array_position(scopes, NULL) IS NULL),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'reauth_required', 'revoked')),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    refresh_lease_id uuid,
    refresh_lease_expires_at timestamptz,
    refreshed_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (discord_id, client_id),
    CHECK ((refresh_lease_id IS NULL) = (refresh_lease_expires_at IS NULL)),
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
    CHECK ((status = 'revoked' AND envelope IS NULL) OR (status <> 'revoked' AND envelope IS NOT NULL)),
    CONSTRAINT encrypted_envelope CHECK (envelope IS NULL OR (
        jsonb_typeof(envelope) = 'object'
        AND envelope ?& ARRAY['v','key_id','nonce','ciphertext','tag']
        AND envelope - ARRAY['v','key_id','nonce','ciphertext','tag'] = '{}'::jsonb
        AND envelope->>'v' = '1'
        AND jsonb_typeof(envelope->'v') = 'number'
        AND envelope->>'key_id' ~ '^[A-Za-z0-9_-]{1,64}$'
        AND envelope->>'nonce' ~ '^[A-Za-z0-9_-]{16}$'
        AND envelope->>'tag' ~ '^[A-Za-z0-9_-]{22}$'
        AND length(envelope->>'ciphertext') BETWEEN 1 AND 16384
        AND envelope->>'ciphertext' ~ '^[A-Za-z0-9_-]+$'
        AND jsonb_typeof(envelope->'key_id') = 'string'
        AND jsonb_typeof(envelope->'nonce') = 'string'
        AND jsonb_typeof(envelope->'ciphertext') = 'string'
        AND jsonb_typeof(envelope->'tag') = 'string'
    ) IS TRUE)
);
CREATE UNIQUE INDEX oauth_current_nonce_unique ON private.oauth_authorizations
    ((envelope->>'key_id'), (envelope->>'nonce')) WHERE envelope IS NOT NULL;
CREATE INDEX oauth_expiration_idx ON private.oauth_authorizations(access_expires_at) WHERE status = 'active';

CREATE TABLE private.oauth_flows (
    id uuid PRIMARY KEY,
    session_hash text NOT NULL CHECK (session_hash ~ '^[a-f0-9]{64}$'),
    state_hash text NOT NULL UNIQUE CHECK (state_hash ~ '^[a-f0-9]{64}$'),
    target_guild_id text NOT NULL CHECK (target_guild_id ~ '^[0-9]{17,20}$'),
    policy_version text NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 100),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);
CREATE INDEX oauth_flows_expiration_idx ON private.oauth_flows(expires_at) WHERE consumed_at IS NULL;

CREATE TABLE private.guild_consents (
    id uuid PRIMARY KEY,
    authorization_id uuid NOT NULL REFERENCES private.oauth_authorizations(id) ON DELETE RESTRICT,
    flow_id uuid NOT NULL UNIQUE REFERENCES private.oauth_flows(id) ON DELETE RESTRICT,
    target_guild_id text NOT NULL CHECK (target_guild_id ~ '^[0-9]{17,20}$'),
    policy_version text NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 100),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','consumed','revoked')),
    granted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    revoked_at timestamptz,
    CHECK (expires_at > granted_at),
    CHECK ((status = 'consumed') = (consumed_at IS NOT NULL)),
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);
CREATE UNIQUE INDEX guild_one_active_consent ON private.guild_consents(authorization_id,target_guild_id) WHERE status='active';
CREATE INDEX guild_eligible_idx ON private.guild_consents(target_guild_id,expires_at,authorization_id) WHERE status='active';

CREATE TABLE private.member_join_operations (
    id uuid PRIMARY KEY,
    consent_id uuid NOT NULL UNIQUE REFERENCES private.guild_consents(id) ON DELETE RESTRICT,
    status text NOT NULL DEFAULT 'in_progress' CHECK (status IN ('in_progress','joined','already_member','failed','uncertain')),
    lease_id uuid NOT NULL UNIQUE,
    lease_expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    CHECK (lease_expires_at > created_at),
    CHECK ((status = 'in_progress') = (completed_at IS NULL))
);
CREATE INDEX member_pending_idx ON private.member_join_operations(lease_expires_at) WHERE status='in_progress';

ALTER TABLE private.oauth_authorizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.oauth_flows ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.guild_consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.member_join_operations ENABLE ROW LEVEL SECURITY;
-- No policies: no client access. service_role has no direct table privileges either.
REVOKE ALL ON TABLE private.oauth_authorizations, private.oauth_flows,
    private.guild_consents, private.member_join_operations FROM PUBLIC, anon, authenticated, service_role;
-- Do not modify permissions on pre-existing objects in a shared private schema.
COMMIT;
