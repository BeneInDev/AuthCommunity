BEGIN;
CREATE TABLE private.guild_configurations (
    guild_id text PRIMARY KEY CHECK(guild_id ~ '^[0-9]{17,20}$'),
    owner_id text NOT NULL CHECK(owner_id ~ '^[0-9]{17,20}$'),
    admin_ids text[] NOT NULL DEFAULT '{}',
    role_id text CHECK(role_id ~ '^[0-9]{17,20}$'),
    log_channel_id text CHECK(log_channel_id ~ '^[0-9]{17,20}$'),
    verification_message text NOT NULL DEFAULT 'Verifique sua conta para este servidor.' CHECK(length(verification_message) BETWEEN 1 AND 1800),
    active boolean NOT NULL DEFAULT false,
    version bigint NOT NULL DEFAULT 1,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK(cardinality(admin_ids)<=20 AND array_position(admin_ids,NULL) IS NULL)
);
ALTER TABLE private.oauth_flows ADD COLUMN origin_guild_id text;
ALTER TABLE private.oauth_flows ADD COLUMN expected_discord_id text;
ALTER TABLE private.oauth_flows ADD COLUMN config_version bigint;
CREATE TABLE private.verification_effects (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    flow_id uuid NOT NULL REFERENCES private.oauth_flows(id),
    guild_id text NOT NULL REFERENCES private.guild_configurations(guild_id),
    discord_id text NOT NULL CHECK(discord_id ~ '^[0-9]{17,20}$'),
    config_version bigint NOT NULL,
    kind text NOT NULL CHECK(kind IN ('role','log')),
    target_id text NOT NULL CHECK(target_id ~ '^[0-9]{17,20}$'),
    nonce text NOT NULL UNIQUE DEFAULT substr(replace(gen_random_uuid()::text,'-',''),1,24),
    status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','done','failed','uncertain','cancelled')),
    attempts integer NOT NULL DEFAULT 0,
    next_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    lease_id uuid,
    lease_until timestamptz,
    first_sent_at timestamptz,
    failure_code text CHECK(failure_code IN ('member_absent','screening_pending','discord_rejected','transport_unknown','configuration_changed','retry_exhausted')),
    message_id text CHECK(message_id ~ '^[0-9]{17,20}$'),
    UNIQUE(flow_id,kind)
);
CREATE INDEX verification_effects_due ON private.verification_effects(next_at) WHERE status IN ('pending','running');
ALTER TABLE private.guild_configurations ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.verification_effects ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON private.guild_configurations,private.verification_effects FROM PUBLIC,anon,authenticated,service_role;

-- p_owner_id must come from a fresh Discord guild response, never request parameters.
CREATE FUNCTION public.ac_guild_sync_owner(p_guild_id text,p_owner_id text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    INSERT INTO private.guild_configurations(guild_id,owner_id) VALUES(p_guild_id,p_owner_id)
    ON CONFLICT(guild_id) DO UPDATE SET owner_id=excluded.owner_id,admin_ids='{}',active=false,
        version=private.guild_configurations.version+1,updated_at=clock_timestamp()
        WHERE private.guild_configurations.owner_id<>excluded.owner_id;
    RETURN true;
END;
$$;
CREATE FUNCTION public.ac_guild_get(p_guild_id text,p_actor_id text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c private.guild_configurations;
BEGIN
    SELECT * INTO c FROM private.guild_configurations WHERE guild_id=p_guild_id;
    IF NOT FOUND OR p_actor_id IS NULL OR NOT(p_actor_id=c.owner_id OR p_actor_id=ANY(c.admin_ids))
    THEN RAISE EXCEPTION 'GUILD_PERMISSION_DENIED'; END IF;
    RETURN to_jsonb(c);
END;
$$;
CREATE FUNCTION public.ac_guild_public(p_guild_id text) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
    SELECT jsonb_build_object('guild_id',guild_id,'version',version,'active',active,'verification_message',verification_message)
    FROM private.guild_configurations WHERE guild_id=p_guild_id AND active;
$$;
CREATE FUNCTION public.ac_guild_save(p_guild_id text,p_actor_id text,p_version bigint,p_role_id text,p_log_channel_id text,
    p_message text,p_active boolean,p_admin_ids text[]) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c private.guild_configurations; v bigint;
BEGIN
    SELECT * INTO c FROM private.guild_configurations WHERE guild_id=p_guild_id FOR UPDATE;
    IF NOT FOUND OR p_actor_id IS NULL OR NOT(p_actor_id=c.owner_id OR p_actor_id=ANY(c.admin_ids))
    THEN RAISE EXCEPTION 'GUILD_PERMISSION_DENIED'; END IF;
    IF c.version<>p_version THEN RAISE EXCEPTION 'GUILD_CONFLICT'; END IF;
    IF p_admin_ids IS NOT NULL AND (p_actor_id<>c.owner_id OR EXISTS(SELECT 1 FROM unnest(p_admin_ids) x WHERE x IS NULL OR x !~ '^[0-9]{17,20}$'))
    THEN RAISE EXCEPTION 'GUILD_PERMISSION_DENIED'; END IF;
    UPDATE private.guild_configurations SET role_id=p_role_id,log_channel_id=p_log_channel_id,
        verification_message=p_message,active=p_active,admin_ids=coalesce(p_admin_ids,admin_ids),
        version=version+1,updated_at=clock_timestamp() WHERE guild_id=p_guild_id RETURNING version INTO v;
    RETURN v;
END;
$$;
CREATE FUNCTION public.ac_guild_create_flow(p_id uuid,p_session_hash text,p_state_hash text,p_guild_id text,
    p_origin_id text,p_discord_id text,p_version bigint,p_policy_version text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    IF p_origin_id IS DISTINCT FROM p_guild_id OR p_discord_id IS NULL OR p_discord_id !~ '^[0-9]{17,20}$' THEN RAISE EXCEPTION 'FLOW_INVALID'; END IF;
    PERFORM 1 FROM private.guild_configurations WHERE guild_id=p_guild_id AND active AND version=p_version FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'GUILD_UNAVAILABLE'; END IF;
    PERFORM public.ac_oauth_create_flow(p_id,p_session_hash,p_state_hash,p_guild_id,p_policy_version);
    UPDATE private.oauth_flows SET origin_guild_id=p_origin_id,expected_discord_id=p_discord_id,config_version=p_version WHERE id=p_id;
    RETURN p_id;
END;
$$;

-- Profile values are an allowlist. No schema/default/trigger changes on public.auth_users.
CREATE FUNCTION public.ac_guild_complete(p jsonb) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c private.guild_configurations; f private.oauth_flows; result uuid; ts timestamptz=clock_timestamp();
BEGIN
    SELECT * INTO c FROM private.guild_configurations WHERE guild_id=p->>'guild_id' AND active FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'GUILD_UNAVAILABLE'; END IF;
    SELECT * INTO f FROM private.oauth_flows WHERE id=(p->>'flow_id')::uuid;
    IF NOT FOUND OR f.origin_guild_id IS DISTINCT FROM c.guild_id OR f.target_guild_id<>c.guild_id
        OR f.config_version IS DISTINCT FROM c.version OR f.expected_discord_id IS DISTINCT FROM p->>'discord_id'
    THEN RAISE EXCEPTION 'FLOW_INVALID'; END IF;
    IF p->>'username' IS NULL OR length(p->>'username') NOT BETWEEN 1 AND 100
        OR jsonb_typeof(p->'username')<>'string' THEN RAISE EXCEPTION 'PROFILE_INVALID'; END IF;
    result=public.ac_oauth_complete_callback((p->>'id')::uuid,(p->>'version')::bigint,p->>'discord_id',p->>'client_id',
        p->'envelope',(p->>'expires_at')::timestamptz,ARRAY(SELECT jsonb_array_elements_text(p->'scopes')),
        (p->>'consent_id')::uuid,f.id,p->>'session_hash',p->>'state_hash',c.guild_id,(p->>'valid_seconds')::integer);
    INSERT INTO public.auth_users(discord_id,username,avatar,verified_at,updated_at)
    VALUES(p->>'discord_id',p->>'username',p->>'avatar',ts,ts)
    ON CONFLICT(discord_id) DO UPDATE SET username=excluded.username,avatar=excluded.avatar,
        verified_at=excluded.verified_at,updated_at=excluded.updated_at;
    IF c.role_id IS NOT NULL THEN
        INSERT INTO private.verification_effects(flow_id,guild_id,discord_id,config_version,kind,target_id)
        VALUES(f.id,c.guild_id,p->>'discord_id',c.version,'role',c.role_id);
    END IF;
    IF c.log_channel_id IS NOT NULL THEN
        INSERT INTO private.verification_effects(flow_id,guild_id,discord_id,config_version,kind,target_id)
        VALUES(f.id,c.guild_id,p->>'discord_id',c.version,'log',c.log_channel_id);
    END IF;
    RETURN result;
END;
$$;

CREATE FUNCTION public.ac_guild_claim_effect(p_lease_id uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE j private.verification_effects;
BEGIN
    IF p_lease_id IS NULL THEN RAISE EXCEPTION 'LEASE_INVALID'; END IF;
    UPDATE private.verification_effects SET status='uncertain',failure_code='transport_unknown'
    WHERE kind='log' AND first_sent_at<clock_timestamp()-interval '120 seconds'
        AND (status='pending' OR (status='running' AND lease_until<clock_timestamp()));
    UPDATE private.verification_effects SET status='failed',failure_code='retry_exhausted'
    WHERE attempts>=10 AND (status='pending' OR (status='running' AND lease_until<clock_timestamp()));
    SELECT * INTO j FROM private.verification_effects WHERE attempts<10 AND
        ((status='pending' AND next_at<=clock_timestamp()) OR (status='running' AND lease_until<clock_timestamp()))
        ORDER BY next_at,id FOR UPDATE SKIP LOCKED LIMIT 1;
    IF NOT FOUND THEN RETURN NULL; END IF;
    UPDATE private.verification_effects SET status='running',lease_id=p_lease_id,lease_until=clock_timestamp()+interval '60 seconds',attempts=attempts+1
        WHERE id=j.id RETURNING * INTO j;
    RETURN to_jsonb(j);
END;
$$;
CREATE FUNCTION public.ac_guild_dispatch_effect(p_id uuid,p_lease_id uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE j private.verification_effects;
BEGIN
    SELECT * INTO j FROM private.verification_effects WHERE id=p_id AND lease_id=p_lease_id AND status='running'
        AND lease_until>clock_timestamp()+interval '15 seconds' FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    PERFORM 1 FROM private.guild_configurations WHERE guild_id=j.guild_id AND active AND version=j.config_version
        AND ((j.kind='role' AND role_id=j.target_id) OR (j.kind='log' AND log_channel_id=j.target_id)) FOR SHARE;
    IF NOT FOUND THEN
        UPDATE private.verification_effects SET status='cancelled',failure_code='configuration_changed' WHERE id=j.id; RETURN false;
    END IF;
    IF j.kind='log' AND j.first_sent_at<clock_timestamp()-interval '120 seconds' THEN
        UPDATE private.verification_effects SET status='uncertain',failure_code='transport_unknown' WHERE id=j.id;RETURN false;
    END IF;
    UPDATE private.verification_effects SET first_sent_at=coalesce(first_sent_at,clock_timestamp()) WHERE id=j.id;
    RETURN true;
END;
$$;
CREATE FUNCTION public.ac_guild_finish_effect(p_id uuid,p_lease_id uuid,p_status text,p_code text,p_message_id text,p_delay integer) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    IF p_status IS NULL OR p_status NOT IN ('done','pending','failed','uncertain') OR p_delay IS NULL OR p_delay NOT BETWEEN 0 AND 86400 THEN RAISE EXCEPTION 'RESULT_INVALID'; END IF;
    UPDATE private.verification_effects SET status=CASE WHEN p_status='pending' AND attempts>=10 THEN 'failed' ELSE p_status END,
        failure_code=CASE WHEN p_status='pending' AND attempts>=10 THEN 'retry_exhausted' ELSE p_code END,message_id=p_message_id,
        next_at=clock_timestamp()+make_interval(secs=>p_delay),lease_until=NULL,lease_id=NULL
    WHERE id=p_id AND lease_id=p_lease_id AND status='running' AND lease_until>clock_timestamp();
    RETURN FOUND;
END;
$$;

REVOKE ALL ON FUNCTION public.ac_guild_sync_owner(text,text),public.ac_guild_get(text,text),public.ac_guild_public(text),
    public.ac_guild_save(text,text,bigint,text,text,text,boolean,text[]),public.ac_guild_create_flow(uuid,text,text,text,text,text,bigint,text),
    public.ac_guild_complete(jsonb),public.ac_guild_claim_effect(uuid),public.ac_guild_dispatch_effect(uuid,uuid),
    public.ac_guild_finish_effect(uuid,uuid,text,text,text,integer) FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION public.ac_guild_sync_owner(text,text),public.ac_guild_get(text,text),public.ac_guild_public(text),
    public.ac_guild_save(text,text,bigint,text,text,text,boolean,text[]),public.ac_guild_create_flow(uuid,text,text,text,text,text,bigint,text),
    public.ac_guild_complete(jsonb),public.ac_guild_claim_effect(uuid),public.ac_guild_dispatch_effect(uuid,uuid),
    public.ac_guild_finish_effect(uuid,uuid,text,text,text,integer) TO service_role;
COMMIT;
