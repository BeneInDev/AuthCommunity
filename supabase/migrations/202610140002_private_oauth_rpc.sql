BEGIN;
-- Explicit objects, no dynamic SQL. Fixed search_path prevents object substitution.
-- Functions live in public for PostgREST RPC discovery, EXECUTE is backend-only.
CREATE FUNCTION public.ac_oauth_create_flow(p_id uuid, p_session_hash text, p_state_hash text,
    p_guild_id text, p_policy_version text) RETURNS uuid
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS $$
    INSERT INTO private.oauth_flows(id,session_hash,state_hash,target_guild_id,policy_version,expires_at)
    VALUES(p_id,p_session_hash,p_state_hash,p_guild_id,p_policy_version,clock_timestamp()+interval '10 minutes') RETURNING id;
$$;

-- Initial creation only. Existing/revoked authorizations cannot be resurrected by this function.
CREATE FUNCTION public.ac_oauth_create_authorization(p_id uuid, p_discord_id text, p_client_id text,
    p_envelope jsonb, p_expires_at timestamptz, p_scopes text[]) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF p_expires_at IS NULL OR p_expires_at <= clock_timestamp() THEN RAISE EXCEPTION 'AUTHORIZATION_EXPIRY_INVALID'; END IF;
    INSERT INTO private.oauth_authorizations(id,discord_id,client_id,envelope,access_expires_at,scopes)
    VALUES(p_id,p_discord_id,p_client_id,p_envelope,p_expires_at,p_scopes);
    RETURN 1;
END;
$$;

CREATE FUNCTION public.ac_oauth_get_authorization(p_id uuid) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT to_jsonb(a) FROM private.oauth_authorizations a WHERE id=p_id;
$$;

-- CAS key rotation: cannot overwrite a newer refresh, reactivation or revocation.
CREATE FUNCTION public.ac_oauth_rotate_key(p_id uuid, p_version bigint, p_envelope jsonb) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE v bigint;
BEGIN
    UPDATE private.oauth_authorizations SET envelope=p_envelope,version=version+1,updated_at=clock_timestamp()
    WHERE id=p_id AND version=p_version AND status <> 'revoked' AND refresh_lease_id IS NULL RETURNING version INTO v;
    IF NOT FOUND THEN RAISE EXCEPTION 'AUTHORIZATION_CONFLICT'; END IF;
    RETURN v;
END;
$$;

CREATE FUNCTION public.ac_oauth_claim_refresh(p_id uuid, p_version bigint, p_lease_id uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE a private.oauth_authorizations;
BEGIN
    IF p_lease_id IS NULL THEN RAISE EXCEPTION 'LEASE_INVALID'; END IF;
    UPDATE private.oauth_authorizations SET refresh_lease_id=p_lease_id,
        refresh_lease_expires_at=clock_timestamp()+interval '60 seconds',version=version+1,updated_at=clock_timestamp()
    WHERE id=p_id AND version=p_version AND status='active' AND refresh_lease_id IS NULL RETURNING * INTO a;
    IF NOT FOUND THEN RAISE EXCEPTION 'AUTHORIZATION_CONFLICT'; END IF;
    RETURN to_jsonb(a);
END;
$$;

CREATE FUNCTION public.ac_oauth_finish_refresh(p_id uuid, p_version bigint, p_lease_id uuid,
    p_envelope jsonb, p_expires_at timestamptz, p_scopes text[]) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE v bigint;
BEGIN
    IF p_expires_at IS NULL OR p_expires_at <= clock_timestamp() THEN RAISE EXCEPTION 'AUTHORIZATION_EXPIRY_INVALID'; END IF;
    UPDATE private.oauth_authorizations SET envelope=p_envelope,access_expires_at=p_expires_at,scopes=p_scopes,
        refresh_lease_id=NULL,refresh_lease_expires_at=NULL,refreshed_at=clock_timestamp(),updated_at=clock_timestamp(),version=version+1
    WHERE id=p_id AND version=p_version AND status='active' AND refresh_lease_id=p_lease_id
        AND refresh_lease_expires_at>clock_timestamp() RETURNING version INTO v;
    IF NOT FOUND THEN RAISE EXCEPTION 'AUTHORIZATION_CONFLICT'; END IF;
    RETURN v;
END;
$$;

-- An ambiguous/expired refresh is NOT retried using possibly rotated credentials.
CREATE FUNCTION public.ac_oauth_abandon_refresh(p_id uuid, p_version bigint, p_lease_id uuid) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE v bigint;
BEGIN
    UPDATE private.oauth_authorizations SET status='reauth_required',refresh_lease_id=NULL,
        refresh_lease_expires_at=NULL,updated_at=clock_timestamp(),version=version+1
    WHERE id=p_id AND version=p_version AND status='active' AND refresh_lease_id=p_lease_id RETURNING version INTO v;
    IF NOT FOUND THEN RAISE EXCEPTION 'AUTHORIZATION_CONFLICT'; END IF;
    RETURN v;
END;
$$;

CREATE FUNCTION public.ac_oauth_revoke_authorization(p_id uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    -- Locks authorization before consents, same order as grant/claim/revoke_consent.
    PERFORM 1 FROM private.oauth_authorizations WHERE id=p_id FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    UPDATE private.oauth_authorizations SET status='revoked',envelope=NULL,revoked_at=clock_timestamp(),
        refresh_lease_id=NULL,refresh_lease_expires_at=NULL,version=version+1,updated_at=clock_timestamp()
    WHERE id=p_id AND status<>'revoked';
    UPDATE private.guild_consents SET status='revoked',revoked_at=clock_timestamp()
    WHERE authorization_id=p_id AND status='active';
    RETURN true;
END;
$$;

-- This endpoint requires an explicit user action verified by the backend, not an import.
-- No fixed consent lifetime policy: caller must choose a reviewed duration, at most 90 days.
CREATE FUNCTION public.ac_oauth_grant_consent(p_id uuid, p_authorization_id uuid, p_flow_id uuid,
    p_session_hash text, p_state_hash text, p_accepted boolean, p_valid_seconds integer) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE f private.oauth_flows;
BEGIN
    IF p_accepted IS DISTINCT FROM true OR p_valid_seconds IS NULL OR p_valid_seconds NOT BETWEEN 1 AND 7776000
    THEN RAISE EXCEPTION 'CONSENT_INVALID'; END IF;
    PERFORM 1 FROM private.oauth_authorizations WHERE id=p_authorization_id AND status='active'
        AND 'guilds.join'=ANY(scopes) AND refresh_lease_id IS NULL FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'AUTHORIZATION_UNAVAILABLE'; END IF;
    UPDATE private.oauth_flows SET consumed_at=clock_timestamp() WHERE id=p_flow_id AND consumed_at IS NULL
        AND expires_at>clock_timestamp() AND session_hash=p_session_hash AND state_hash=p_state_hash RETURNING * INTO f;
    IF NOT FOUND THEN RAISE EXCEPTION 'FLOW_INVALID'; END IF;
    UPDATE private.guild_consents SET status='revoked',revoked_at=clock_timestamp()
        WHERE authorization_id=p_authorization_id AND target_guild_id=f.target_guild_id AND status='active';
    INSERT INTO private.guild_consents(id,authorization_id,flow_id,target_guild_id,policy_version,expires_at)
    VALUES(p_id,p_authorization_id,p_flow_id,f.target_guild_id,f.policy_version,clock_timestamp()+make_interval(secs=>p_valid_seconds));
    RETURN p_id;
END;
$$;

CREATE FUNCTION public.ac_oauth_revoke_consent(p_id uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE auth_id uuid;
BEGIN
    SELECT authorization_id INTO auth_id FROM private.guild_consents WHERE id=p_id;
    IF NOT FOUND THEN RETURN false; END IF;
    PERFORM 1 FROM private.oauth_authorizations WHERE id=auth_id FOR UPDATE;
    UPDATE private.guild_consents SET status='revoked',revoked_at=clock_timestamp() WHERE id=p_id AND status='active';
    RETURN FOUND;
END;
$$;

CREATE FUNCTION public.ac_oauth_list_eligible(p_guild_id text, p_client_id text, p_limit integer)
RETURNS TABLE(consent_id uuid, authorization_id uuid, discord_id text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION 'LIMIT_INVALID'; END IF;
    RETURN QUERY SELECT c.id,a.id,a.discord_id FROM private.guild_consents c
    JOIN private.oauth_authorizations a ON a.id=c.authorization_id
    WHERE c.target_guild_id=p_guild_id AND c.status='active' AND c.expires_at>clock_timestamp()
        AND a.client_id=p_client_id AND a.status='active' AND a.refresh_lease_id IS NULL
        AND a.access_expires_at>clock_timestamp()+interval '30 seconds' AND 'guilds.join'=ANY(a.scopes)
    ORDER BY c.granted_at,c.id LIMIT p_limit;
END;
$$;

CREATE FUNCTION public.ac_oauth_claim_join(p_id uuid,p_consent_id uuid,p_guild_id text,p_client_id text,p_lease_id uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE c private.guild_consents; a private.oauth_authorizations;
BEGIN
    IF p_lease_id IS NULL THEN RAISE EXCEPTION 'LEASE_INVALID'; END IF;
    SELECT * INTO c FROM private.guild_consents WHERE id=p_consent_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'CONSENT_UNAVAILABLE'; END IF;
    SELECT * INTO a FROM private.oauth_authorizations WHERE id=c.authorization_id FOR UPDATE;
    IF a.status<>'active' OR a.client_id<>p_client_id OR p_client_id IS NULL OR a.refresh_lease_id IS NOT NULL
        OR a.access_expires_at<=clock_timestamp()+interval '30 seconds' OR NOT ('guilds.join'=ANY(a.scopes))
    THEN RAISE EXCEPTION 'AUTHORIZATION_UNAVAILABLE'; END IF;
    SELECT * INTO c FROM private.guild_consents WHERE id=p_consent_id AND target_guild_id=p_guild_id
        AND status='active' AND expires_at>clock_timestamp() FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'CONSENT_UNAVAILABLE'; END IF;
    INSERT INTO private.member_join_operations(id,consent_id,lease_id,lease_expires_at)
    VALUES(p_id,p_consent_id,p_lease_id,clock_timestamp()+interval '60 seconds');
    -- Reserve exactly once. Even ambiguous failures cannot silently rejoin a user.
    UPDATE private.guild_consents SET status='consumed',consumed_at=clock_timestamp() WHERE id=c.id;
    RETURN jsonb_build_object('operation_id',p_id,'authorization_id',a.id,'discord_id',a.discord_id,'client_id',a.client_id);
END;
$$;

CREATE FUNCTION public.ac_oauth_finish_join(p_id uuid,p_lease_id uuid,p_result text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF p_result IS NULL OR p_result NOT IN ('joined','already_member','failed','uncertain') THEN RAISE EXCEPTION 'RESULT_INVALID'; END IF;
    UPDATE private.member_join_operations SET status=p_result,completed_at=clock_timestamp()
    WHERE id=p_id AND lease_id=p_lease_id AND status='in_progress'
        AND (lease_expires_at>clock_timestamp() OR p_result='uncertain');
    RETURN FOUND;
END;
$$;

-- Revoke defaults (including Supabase defaults) before this transaction commits.
REVOKE ALL ON FUNCTION public.ac_oauth_create_flow(uuid,text,text,text,text) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.ac_oauth_create_authorization(uuid,text,text,jsonb,timestamptz,text[]) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.ac_oauth_get_authorization(uuid) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.ac_oauth_rotate_key(uuid,bigint,jsonb) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.ac_oauth_claim_refresh(uuid,bigint,uuid) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.ac_oauth_finish_refresh(uuid,bigint,uuid,jsonb,timestamptz,text[]) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.ac_oauth_abandon_refresh(uuid,bigint,uuid) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.ac_oauth_revoke_authorization(uuid) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.ac_oauth_grant_consent(uuid,uuid,uuid,text,text,boolean,integer) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.ac_oauth_revoke_consent(uuid) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.ac_oauth_list_eligible(text,text,integer) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.ac_oauth_claim_join(uuid,uuid,text,text,uuid) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.ac_oauth_finish_join(uuid,uuid,text) FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_create_flow(uuid,text,text,text,text) TO service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_create_authorization(uuid,text,text,jsonb,timestamptz,text[]) TO service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_get_authorization(uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_rotate_key(uuid,bigint,jsonb) TO service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_claim_refresh(uuid,bigint,uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_finish_refresh(uuid,bigint,uuid,jsonb,timestamptz,text[]) TO service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_abandon_refresh(uuid,bigint,uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_revoke_authorization(uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_grant_consent(uuid,uuid,uuid,text,text,boolean,integer) TO service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_revoke_consent(uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_list_eligible(text,text,integer) TO service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_claim_join(uuid,uuid,text,text,uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_finish_join(uuid,uuid,text) TO service_role;
COMMIT;
