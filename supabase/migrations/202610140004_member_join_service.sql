BEGIN;
-- Durable gateway continuity and departures; no legacy import and no auth_users changes.
CREATE TABLE private.guild_join_safety (
    guild_id text NOT NULL CHECK (guild_id ~ '^[0-9]{17,20}$'),
    client_id text NOT NULL CHECK (client_id ~ '^[0-9]{17,20}$'),
    observer_id uuid NOT NULL,
    epoch_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    healthy_until timestamptz NOT NULL,
    cooldown_until timestamptz,
    PRIMARY KEY(guild_id,client_id)
);
CREATE TABLE private.guild_departures (
    guild_id text NOT NULL CHECK (guild_id ~ '^[0-9]{17,20}$'),
    client_id text NOT NULL CHECK (client_id ~ '^[0-9]{17,20}$'),
    discord_id text NOT NULL CHECK (discord_id ~ '^[0-9]{17,20}$'),
    departed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(guild_id,client_id,discord_id)
);
ALTER TABLE private.guild_join_safety ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.guild_departures ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON private.guild_join_safety,private.guild_departures FROM PUBLIC,anon,authenticated,service_role;
ALTER TABLE private.member_join_operations ADD COLUMN dispatched_at timestamptz;
ALTER TABLE private.member_join_operations ADD COLUMN failure_code text
    CHECK (failure_code IN ('rate_limited','discord_rejected','transport_unknown','preflight_failed','authorization_unavailable','persistence_unknown'));
ALTER TABLE private.member_join_operations ADD COLUMN http_status integer CHECK (http_status BETWEEN 100 AND 599);
ALTER TABLE private.member_join_operations DROP CONSTRAINT member_join_operations_status_check;
ALTER TABLE private.member_join_operations ADD CONSTRAINT member_join_operations_status_check
    CHECK (status IN ('in_progress','joined','already_member','pending','failed','uncertain'));

CREATE FUNCTION public.ac_oauth_watch_guild(p_guild_id text,p_client_id text,p_observer_id uuid,p_reset boolean)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE s private.guild_join_safety;
BEGIN
    IF p_observer_id IS NULL OR p_reset IS NULL THEN RAISE EXCEPTION 'OBSERVER_INVALID'; END IF;
    INSERT INTO private.guild_join_safety(guild_id,client_id,observer_id,healthy_until)
    VALUES(p_guild_id,p_client_id,p_observer_id,clock_timestamp()) ON CONFLICT DO NOTHING;
    SELECT * INTO s FROM private.guild_join_safety WHERE guild_id=p_guild_id AND client_id=p_client_id FOR UPDATE;
    IF s.observer_id<>p_observer_id AND s.healthy_until>clock_timestamp() THEN RETURN false; END IF;
    UPDATE private.guild_join_safety SET observer_id=p_observer_id,healthy_until=clock_timestamp()+interval '30 seconds',
        epoch_at=CASE WHEN p_reset OR s.observer_id<>p_observer_id OR s.healthy_until<=clock_timestamp()
            THEN clock_timestamp() ELSE epoch_at END
    WHERE guild_id=p_guild_id AND client_id=p_client_id;
    RETURN true;
END;
$$;

CREATE FUNCTION public.ac_oauth_pause_guild(p_guild_id text,p_client_id text,p_observer_id uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    UPDATE private.guild_join_safety SET healthy_until=clock_timestamp(),epoch_at=clock_timestamp()
    WHERE guild_id=p_guild_id AND client_id=p_client_id AND observer_id=p_observer_id;
    RETURN FOUND;
END;
$$;

-- Discord does not reliably distinguish voluntary leave from kick here: block both.
CREATE FUNCTION public.ac_oauth_record_departure(p_guild_id text,p_client_id text,p_discord_id text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    PERFORM 1 FROM private.guild_join_safety WHERE guild_id=p_guild_id AND client_id=p_client_id FOR UPDATE;
    INSERT INTO private.guild_departures(guild_id,client_id,discord_id) VALUES(p_guild_id,p_client_id,p_discord_id)
    ON CONFLICT(guild_id,client_id,discord_id) DO UPDATE SET departed_at=clock_timestamp();
    UPDATE private.guild_consents c SET status='revoked',revoked_at=clock_timestamp()
    FROM private.oauth_authorizations a WHERE c.authorization_id=a.id AND a.discord_id=p_discord_id
        AND a.client_id=p_client_id AND c.target_guild_id=p_guild_id AND c.status='active';
    RETURN true;
END;
$$;

-- Includes expired access tokens so the backend can refresh before reserving a consent.
CREATE FUNCTION public.ac_oauth_join_candidates(p_guild_id text,p_client_id text,p_observer_id uuid,p_limit integer)
RETURNS TABLE(consent_id uuid,authorization_id uuid,discord_id text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION 'LIMIT_INVALID'; END IF;
    RETURN QUERY SELECT c.id,a.id,a.discord_id FROM private.guild_consents c
    JOIN private.oauth_authorizations a ON a.id=c.authorization_id
    JOIN private.oauth_flows f ON f.id=c.flow_id
    JOIN private.guild_join_safety s ON s.guild_id=c.target_guild_id AND s.client_id=a.client_id
    LEFT JOIN private.guild_departures d ON d.guild_id=c.target_guild_id AND d.client_id=a.client_id AND d.discord_id=a.discord_id
    WHERE c.target_guild_id=p_guild_id AND a.client_id=p_client_id AND s.observer_id=p_observer_id
        AND s.healthy_until>clock_timestamp() AND (s.cooldown_until IS NULL OR s.cooldown_until<=clock_timestamp())
        AND f.created_at>s.epoch_at AND (d.departed_at IS NULL OR f.created_at>d.departed_at)
        AND c.status='active' AND c.expires_at>clock_timestamp() AND a.status='active'
        AND a.refresh_lease_id IS NULL AND 'guilds.join'=ANY(a.scopes)
    ORDER BY c.granted_at,c.id LIMIT p_limit;
END;
$$;

CREATE FUNCTION public.ac_oauth_reserve_member(p_id uuid,p_consent_id uuid,p_guild_id text,p_client_id text,p_lease_id uuid,p_observer_id uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    PERFORM 1 FROM private.guild_join_safety WHERE guild_id=p_guild_id AND client_id=p_client_id
        AND observer_id=p_observer_id AND healthy_until>clock_timestamp()
        AND (cooldown_until IS NULL OR cooldown_until<=clock_timestamp()) FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'OBSERVATION_UNAVAILABLE'; END IF;
    PERFORM 1 FROM private.guild_consents c JOIN private.oauth_flows f ON f.id=c.flow_id
    JOIN private.oauth_authorizations a ON a.id=c.authorization_id
    JOIN private.guild_join_safety s ON s.guild_id=p_guild_id AND s.client_id=p_client_id
    LEFT JOIN private.guild_departures d ON d.guild_id=p_guild_id AND d.client_id=p_client_id AND d.discord_id=a.discord_id
    WHERE c.id=p_consent_id AND f.created_at>s.epoch_at AND (d.departed_at IS NULL OR f.created_at>d.departed_at);
    IF NOT FOUND THEN RAISE EXCEPTION 'CONSENT_UNAVAILABLE'; END IF;
    RETURN public.ac_oauth_claim_join(p_id,p_consent_id,p_guild_id,p_client_id,p_lease_id);
END;
$$;

-- One final authorization check and one dispatch permit. No retry of a timed-out PUT.
CREATE FUNCTION public.ac_oauth_dispatch_member(p_id uuid,p_lease_id uuid,p_observer_id uuid,p_guild_id text,p_client_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a private.oauth_authorizations; auth_id uuid;
BEGIN
    PERFORM 1 FROM private.guild_join_safety WHERE guild_id=p_guild_id AND client_id=p_client_id
        AND observer_id=p_observer_id AND healthy_until>clock_timestamp()
        AND (cooldown_until IS NULL OR cooldown_until<=clock_timestamp()) FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'OBSERVATION_UNAVAILABLE'; END IF;
    SELECT c.authorization_id INTO auth_id FROM private.member_join_operations o
        JOIN private.guild_consents c ON c.id=o.consent_id WHERE o.id=p_id;
    SELECT * INTO a FROM private.oauth_authorizations WHERE id=auth_id FOR UPDATE;
    IF NOT FOUND OR a.status<>'active' OR a.client_id<>p_client_id OR a.refresh_lease_id IS NOT NULL
        OR a.access_expires_at<=clock_timestamp()+interval '15 seconds' OR NOT ('guilds.join'=ANY(a.scopes))
    THEN RAISE EXCEPTION 'AUTHORIZATION_UNAVAILABLE'; END IF;
    UPDATE private.member_join_operations o SET dispatched_at=clock_timestamp()
    FROM private.guild_consents c JOIN private.oauth_flows f ON f.id=c.flow_id
    JOIN private.guild_join_safety s ON s.guild_id=c.target_guild_id AND s.client_id=p_client_id
    LEFT JOIN private.guild_departures d ON d.guild_id=s.guild_id AND d.client_id=s.client_id AND d.discord_id=a.discord_id
    WHERE o.id=p_id AND o.consent_id=c.id AND o.lease_id=p_lease_id AND o.status='in_progress'
        AND o.dispatched_at IS NULL AND o.lease_expires_at>clock_timestamp()+interval '15 seconds'
        AND c.status='consumed' AND c.target_guild_id=p_guild_id AND c.expires_at>clock_timestamp()
        AND f.created_at>s.epoch_at AND (d.departed_at IS NULL OR f.created_at>d.departed_at);
    IF NOT FOUND THEN RAISE EXCEPTION 'OPERATION_UNAVAILABLE'; END IF;
    RETURN to_jsonb(a);
END;
$$;

CREATE FUNCTION public.ac_oauth_finish_member(p_id uuid,p_lease_id uuid,p_result text,p_failure_code text,p_http_status integer,p_retry_seconds integer)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE guild text; app text;
BEGIN
    IF p_result IS NULL OR p_result NOT IN ('joined','already_member','pending','failed','uncertain')
        OR p_retry_seconds IS NULL OR p_retry_seconds NOT BETWEEN 0 AND 604800
    THEN RAISE EXCEPTION 'RESULT_INVALID'; END IF;
    SELECT c.target_guild_id,a.client_id INTO guild,app FROM private.member_join_operations o
        JOIN private.guild_consents c ON c.id=o.consent_id JOIN private.oauth_authorizations a ON a.id=c.authorization_id
        WHERE o.id=p_id AND o.lease_id=p_lease_id;
    IF NOT FOUND THEN RETURN false; END IF;
    -- Same lock order as reserve/dispatch/departure.
    PERFORM 1 FROM private.guild_join_safety WHERE guild_id=guild AND client_id=app FOR UPDATE;
    UPDATE private.member_join_operations SET status=p_result,completed_at=clock_timestamp(),
        failure_code=p_failure_code,http_status=p_http_status
    WHERE id=p_id AND lease_id=p_lease_id AND status='in_progress'
        AND (lease_expires_at>clock_timestamp() OR p_result='uncertain');
    IF NOT FOUND THEN RETURN false; END IF;
    IF p_retry_seconds>0 THEN
        UPDATE private.guild_join_safety SET cooldown_until=greatest(coalesce(cooldown_until,clock_timestamp()),
            clock_timestamp()+make_interval(secs=>p_retry_seconds)) WHERE guild_id=guild AND client_id=app;
    END IF;
    RETURN true;
END;
$$;

-- The previous unguarded reservation is now internal to the guarded function.
REVOKE EXECUTE ON FUNCTION public.ac_oauth_claim_join(uuid,uuid,text,text,uuid) FROM service_role;
REVOKE ALL ON FUNCTION public.ac_oauth_watch_guild(text,text,uuid,boolean) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.ac_oauth_pause_guild(text,text,uuid) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.ac_oauth_record_departure(text,text,text) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.ac_oauth_join_candidates(text,text,uuid,integer) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.ac_oauth_reserve_member(uuid,uuid,text,text,uuid,uuid) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.ac_oauth_dispatch_member(uuid,uuid,uuid,text,text) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.ac_oauth_finish_member(uuid,uuid,text,text,integer,integer) FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_watch_guild(text,text,uuid,boolean) TO service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_pause_guild(text,text,uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_record_departure(text,text,text) TO service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_join_candidates(text,text,uuid,integer) TO service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_reserve_member(uuid,uuid,text,text,uuid,uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_dispatch_member(uuid,uuid,uuid,text,text) TO service_role;
GRANT EXECUTE ON FUNCTION public.ac_oauth_finish_member(uuid,uuid,text,text,integer,integer) TO service_role;
COMMIT;
