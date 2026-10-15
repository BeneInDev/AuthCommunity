BEGIN;
-- Additive migration: never touches public.auth_users or imports legacy consent.
ALTER TABLE private.oauth_flows ADD COLUMN callback_claimed_at timestamptz;
ALTER TABLE private.oauth_authorizations DROP CONSTRAINT oauth_authorizations_status_check;
ALTER TABLE private.oauth_authorizations ADD CONSTRAINT oauth_authorizations_status_check
    CHECK (status IN ('active','reauth_required','revocation_pending','revoked'));

CREATE FUNCTION public.ac_oauth_claim_callback(p_id uuid,p_session_hash text,p_state_hash text,p_guild_id text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    UPDATE private.oauth_flows SET callback_claimed_at=clock_timestamp()
    WHERE id=p_id AND session_hash=p_session_hash AND state_hash=p_state_hash AND target_guild_id=p_guild_id
        AND expires_at>clock_timestamp() AND consumed_at IS NULL AND callback_claimed_at IS NULL;
    RETURN FOUND;
END;
$$;

CREATE FUNCTION public.ac_oauth_find_authorization(p_discord_id text,p_client_id text)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
    SELECT jsonb_build_object('id',id,'version',version) FROM private.oauth_authorizations
    WHERE discord_id=p_discord_id AND client_id=p_client_id;
$$;

-- All three changes commit together: credentials, flow consumption, destination consent.
-- Callback claim happens earlier, intentionally preventing retries of an exchanged code.
CREATE FUNCTION public.ac_oauth_complete_callback(p_id uuid,p_version bigint,p_discord_id text,p_client_id text,
    p_envelope jsonb,p_expires_at timestamptz,p_scopes text[],p_consent_id uuid,p_flow_id uuid,
    p_session_hash text,p_state_hash text,p_guild_id text,p_valid_seconds integer)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    IF p_expires_at IS NULL OR p_expires_at<=clock_timestamp()
        OR NOT ('identify'=ANY(p_scopes) AND 'guilds.join'=ANY(p_scopes)) OR p_scopes IS NULL
    THEN RAISE EXCEPTION 'AUTHORIZATION_INVALID'; END IF;
    IF p_version IS NULL THEN
        INSERT INTO private.oauth_authorizations(id,discord_id,client_id,envelope,access_expires_at,scopes)
        VALUES(p_id,p_discord_id,p_client_id,p_envelope,p_expires_at,p_scopes);
    ELSE
        UPDATE private.oauth_authorizations SET envelope=p_envelope,access_expires_at=p_expires_at,scopes=p_scopes,
            status='active',revoked_at=NULL,version=version+1,updated_at=clock_timestamp()
        WHERE id=p_id AND discord_id=p_discord_id AND client_id=p_client_id AND version=p_version
            AND status IN ('active','reauth_required','revoked') AND refresh_lease_id IS NULL;
        IF NOT FOUND THEN RAISE EXCEPTION 'AUTHORIZATION_CONFLICT'; END IF;
    END IF;
    PERFORM 1 FROM private.oauth_flows WHERE id=p_flow_id AND callback_claimed_at IS NOT NULL
        AND target_guild_id=p_guild_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'FLOW_INVALID'; END IF;
    PERFORM public.ac_oauth_grant_consent(p_consent_id,p_id,p_flow_id,p_session_hash,p_state_hash,true,p_valid_seconds);
    RETURN p_id;
END;
$$;

-- Disable local use first; retain encrypted credentials until Discord confirms revocation.
CREATE FUNCTION public.ac_oauth_begin_revocation(p_id uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a private.oauth_authorizations;
BEGIN
    SELECT * INTO a FROM private.oauth_authorizations WHERE id=p_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'AUTHORIZATION_UNAVAILABLE'; END IF;
    IF a.status='revoked' THEN RETURN to_jsonb(a); END IF;
    IF a.status='revocation_pending' AND a.refresh_lease_expires_at>clock_timestamp()
    THEN RAISE EXCEPTION 'AUTHORIZATION_CONFLICT'; END IF;
    UPDATE private.oauth_authorizations SET status='revocation_pending',version=version+1,
        refresh_lease_id=gen_random_uuid(),refresh_lease_expires_at=clock_timestamp()+interval '60 seconds',updated_at=clock_timestamp()
        WHERE id=p_id RETURNING * INTO a;
    UPDATE private.guild_consents SET status='revoked',revoked_at=clock_timestamp()
        WHERE authorization_id=p_id AND status='active';
    RETURN to_jsonb(a);
END;
$$;

CREATE FUNCTION public.ac_oauth_finish_revocation(p_id uuid,p_version bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    PERFORM 1 FROM private.oauth_authorizations WHERE id=p_id AND version=p_version
        AND status='revocation_pending' FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'AUTHORIZATION_CONFLICT'; END IF;
    RETURN public.ac_oauth_revoke_authorization(p_id);
END;
$$;

REVOKE ALL ON FUNCTION public.ac_oauth_claim_callback(uuid,text,text,text) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.ac_oauth_find_authorization(text,text) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.ac_oauth_complete_callback(uuid,bigint,text,text,jsonb,timestamptz,text[],uuid,uuid,text,text,text,integer) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.ac_oauth_begin_revocation(uuid) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.ac_oauth_finish_revocation(uuid,bigint) FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_claim_callback(uuid,text,text,text) TO service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_find_authorization(text,text) TO service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_complete_callback(uuid,bigint,text,text,jsonb,timestamptz,text[],uuid,uuid,text,text,text,integer) TO service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_begin_revocation(uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_finish_revocation(uuid,bigint) TO service_role;
COMMIT;
