--
-- PostgreSQL database dump
--


-- Dumped from database version 17.6
-- Dumped by pg_dump version 18.3

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA public;


--
-- Name: SCHEMA public; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON SCHEMA public IS 'standard public schema';


--
-- Name: activate_gated_storage_subs(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.activate_gated_storage_subs(p_pubkey text) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO ''
    AS $$
DECLARE
  v_count integer;
BEGIN
  UPDATE public.paddle_storage_subs
     SET gated = false,
         updated_at = now()
   WHERE pubkey = p_pubkey
     AND gated = true;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END;
$$;


--
-- Name: adjust_blob_bytes(bigint); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.adjust_blob_bytes(delta bigint) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO ''
    AS $$
begin
  perform public.adjust_image_bytes(delta);
end;
$$;


--
-- Name: adjust_image_bytes(bigint); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.adjust_image_bytes(delta bigint) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO ''
    AS $$
DECLARE
  v_pubkey text;
  v_max_total_bytes bigint;
  v_max_image_bytes bigint;
  v_total_bytes bigint;
  v_image_bytes bigint;
BEGIN
  v_pubkey := auth.jwt() -> 'app_metadata' ->> 'pubkey';
  IF v_pubkey IS NULL THEN
    RAISE EXCEPTION 'pubkey not linked';
  END IF;

  INSERT INTO public.pubkey_quotas (user_pubkey, note_count, total_bytes, image_bytes, updated_at)
  VALUES (v_pubkey, 0, 0, greatest(delta, 0), now())
  ON CONFLICT (user_pubkey) DO UPDATE
    SET image_bytes = greatest(public.pubkey_quotas.image_bytes + delta, 0),
        updated_at  = now()
  RETURNING total_bytes, image_bytes INTO v_total_bytes, v_image_bytes;

  -- Enforce on growth only. Deletes always succeed.
  IF delta > 0 THEN
    SELECT max_total_bytes, max_image_bytes
      INTO v_max_total_bytes, v_max_image_bytes
      FROM public.quota_limits_for_pubkey(v_pubkey);

    -- Gate 1: per-type image cap.
    IF v_image_bytes > v_max_image_bytes THEN
      UPDATE public.pubkey_quotas
         SET image_bytes = greatest(image_bytes - delta, 0),
             updated_at  = now()
       WHERE user_pubkey = v_pubkey;

      RAISE EXCEPTION 'Quota exceeded: image storage % bytes > limit % bytes',
        v_image_bytes, v_max_image_bytes
        USING errcode = 'check_violation';
    END IF;

    -- Gate 2: combined storage cap (notes + images).
    IF (v_total_bytes + v_image_bytes) > v_max_total_bytes THEN
      UPDATE public.pubkey_quotas
         SET image_bytes = greatest(image_bytes - delta, 0),
             updated_at  = now()
       WHERE user_pubkey = v_pubkey;

      RAISE EXCEPTION 'Quota exceeded: combined storage % bytes > limit % bytes',
        (v_total_bytes + v_image_bytes), v_max_total_bytes
        USING errcode = 'check_violation';
    END IF;
  END IF;
END;
$$;


--
-- Name: admin_abuse_allowlist_add(text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_abuse_allowlist_add(target_pubkey text, p_reason text DEFAULT NULL::text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  v_caller text;
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  v_caller := (auth.jwt() -> 'user_metadata' ->> 'pubkey');

  INSERT INTO public.abuse_allowlist (pubkey, added_by_pubkey, reason)
  VALUES (target_pubkey, v_caller, p_reason)
  ON CONFLICT (pubkey) DO UPDATE
    SET added_at = now(),
        added_by_pubkey = EXCLUDED.added_by_pubkey,
        reason = EXCLUDED.reason;
END;
$$;


--
-- Name: admin_abuse_allowlist_list(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_abuse_allowlist_list() RETURNS TABLE(pubkey text, added_at timestamp with time zone, added_by_pubkey text, reason text)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  RETURN QUERY
  SELECT a.pubkey, a.added_at, a.added_by_pubkey, a.reason
  FROM public.abuse_allowlist a
  ORDER BY a.added_at DESC;
END;
$$;


--
-- Name: admin_abuse_allowlist_remove(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_abuse_allowlist_remove(target_pubkey text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  DELETE FROM public.abuse_allowlist WHERE pubkey = target_pubkey;
END;
$$;


--
-- Name: admin_abuse_device_cycling(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_abuse_device_cycling() RETURNS TABLE(pubkey text, devices_7d bigint, total_devices bigint, is_pro boolean)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  RETURN QUERY
  SELECT
    d.pubkey,
    count(*) FILTER (WHERE d.created_at > now() - interval '7 days')::bigint AS devices_7d,
    count(*)::bigint AS total_devices,
    (EXISTS (SELECT 1 FROM public.pro_pubkeys pp WHERE pp.pubkey = d.pubkey)) AS is_pro
  FROM public.devices d
  WHERE NOT EXISTS (SELECT 1 FROM public.abuse_allowlist a WHERE a.pubkey = d.pubkey)
  GROUP BY d.pubkey
  HAVING count(*) FILTER (WHERE d.created_at > now() - interval '7 days') > 3
  ORDER BY devices_7d DESC
  LIMIT 50;
END;
$$;


--
-- Name: admin_abuse_device_farms(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_abuse_device_farms() RETURNS TABLE(pubkey text, device_count bigint, active_count bigint, is_pro boolean, note_count bigint)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  RETURN QUERY
  SELECT
    d.pubkey,
    count(*)::bigint AS device_count,
    count(*) FILTER (WHERE d.last_seen_at > now() - interval '30 days')::bigint AS active_count,
    (EXISTS (SELECT 1 FROM public.pro_pubkeys pp WHERE pp.pubkey = d.pubkey)) AS is_pro,
    coalesce(q.note_count, 0)::bigint AS note_count
  FROM public.devices d
  LEFT JOIN public.pubkey_quotas q ON q.user_pubkey = d.pubkey
  WHERE NOT EXISTS (SELECT 1 FROM public.abuse_allowlist a WHERE a.pubkey = d.pubkey)
  GROUP BY d.pubkey, q.note_count
  HAVING count(*) > 5
  ORDER BY device_count DESC
  LIMIT 50;
END;
$$;


--
-- Name: admin_abuse_ghost_writers(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_abuse_ghost_writers() RETURNS TABLE(pubkey text, note_count bigint, total_bytes bigint, last_seen_at timestamp with time zone, days_silent bigint)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  RETURN QUERY
  SELECT
    q.user_pubkey AS pubkey,
    q.note_count,
    q.total_bytes,
    latest.last_seen AS last_seen_at,
    extract(day FROM now() - latest.last_seen)::bigint AS days_silent
  FROM public.pubkey_quotas q
  LEFT JOIN LATERAL (
    SELECT max(d.last_seen_at) AS last_seen
    FROM public.devices d
    WHERE d.pubkey = q.user_pubkey
  ) latest ON true
  WHERE q.note_count > 0
    AND (latest.last_seen IS NULL OR latest.last_seen < now() - interval '90 days')
    AND NOT EXISTS (SELECT 1 FROM public.abuse_allowlist a WHERE a.pubkey = q.user_pubkey)
  ORDER BY q.note_count DESC
  LIMIT 50;
END;
$$;


--
-- Name: admin_abuse_note_hoarders(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_abuse_note_hoarders() RETURNS TABLE(pubkey text, note_count bigint, total_bytes bigint, is_pro boolean, last_seen_at timestamp with time zone)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  RETURN QUERY
  SELECT
    q.user_pubkey AS pubkey,
    q.note_count,
    q.total_bytes,
    (EXISTS (SELECT 1 FROM public.pro_pubkeys pp WHERE pp.pubkey = q.user_pubkey)) AS is_pro,
    (SELECT max(d.last_seen_at) FROM public.devices d WHERE d.pubkey = q.user_pubkey) AS last_seen_at
  FROM public.pubkey_quotas q
  WHERE q.note_count > 1000
    AND NOT EXISTS (SELECT 1 FROM public.abuse_allowlist a WHERE a.pubkey = q.user_pubkey)
  ORDER BY q.note_count DESC
  LIMIT 50;
END;
$$;


--
-- Name: admin_abuse_oversized_notes(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_abuse_oversized_notes() RETURNS TABLE(pubkey text, note_id uuid, ciphertext_bytes bigint, created_at timestamp with time zone, updated_at timestamp with time zone)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  RETURN QUERY
  SELECT
    n.user_pubkey AS pubkey,
    n.id AS note_id,
    octet_length(n.ciphertext)::bigint AS ciphertext_bytes,
    n.created_at,
    n.updated_at
  FROM public.notes n
  WHERE octet_length(n.ciphertext) > 512000
    AND NOT EXISTS (SELECT 1 FROM public.abuse_allowlist a WHERE a.pubkey = n.user_pubkey)
  ORDER BY ciphertext_bytes DESC
  LIMIT 50;
END;
$$;


--
-- Name: admin_abuse_storage_hogs(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_abuse_storage_hogs() RETURNS TABLE(pubkey text, total_bytes bigint, max_bytes bigint, pct numeric, is_pro boolean, note_count bigint)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  RETURN QUERY
  SELECT
    q.user_pubkey AS pubkey,
    q.total_bytes,
    lim.max_total_bytes AS max_bytes,
    round(q.total_bytes::numeric / nullif(lim.max_total_bytes, 0) * 100, 1) AS pct,
    (EXISTS (SELECT 1 FROM public.pro_pubkeys pp WHERE pp.pubkey = q.user_pubkey)) AS is_pro,
    q.note_count
  FROM public.pubkey_quotas q
  CROSS JOIN LATERAL public.quota_limits_for_pubkey(q.user_pubkey) lim
  WHERE q.total_bytes > lim.max_total_bytes * 0.8
    AND NOT EXISTS (SELECT 1 FROM public.abuse_allowlist a WHERE a.pubkey = q.user_pubkey)
  ORDER BY pct DESC
  LIMIT 50;
END;
$$;


--
-- Name: admin_activation_funnel(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_activation_funnel() RETURNS jsonb
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  result jsonb;
  v_total bigint;
  v_linked bigint;
  v_has_notes bigint;
  v_has_device bigint;
  v_active_7d bigint;
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  SELECT count(*) INTO v_total FROM auth.users;

  SELECT count(*) INTO v_linked
  FROM auth.users
  WHERE (raw_app_meta_data ->> 'pubkey') IS NOT NULL;

  SELECT count(DISTINCT user_pubkey) INTO v_has_notes FROM public.notes;

  SELECT count(DISTINCT pubkey) INTO v_has_device FROM public.devices;

  SELECT count(DISTINCT pubkey) INTO v_active_7d
  FROM public.devices
  WHERE last_seen_at > now() - interval '7 days';

  SELECT jsonb_build_object(
    'signed_up', v_total,
    'linked_pubkey', v_linked,
    'wrote_note', v_has_notes,
    'registered_device', v_has_device,
    'active_7d', v_active_7d
  ) INTO result;

  RETURN result;
END;
$$;


--
-- Name: admin_activity_breakdown(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_activity_breakdown() RETURNS jsonb
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  result jsonb;
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  WITH pubkeys AS (
    SELECT DISTINCT (raw_app_meta_data ->> 'pubkey') AS pk
    FROM auth.users
    WHERE (raw_app_meta_data ->> 'pubkey') IS NOT NULL
  ),
  latest_device AS (
    SELECT pubkey AS pk, max(last_seen_at) AS last_active
    FROM public.devices
    GROUP BY pubkey
  )
  SELECT jsonb_build_object(
    'active_7d',  count(*) FILTER (WHERE ld.last_active > now() - interval '7 days'),
    'warm_30d',   count(*) FILTER (WHERE ld.last_active BETWEEN now() - interval '30 days' AND now() - interval '7 days'),
    'dormant',    count(*) FILTER (WHERE ld.last_active < now() - interval '30 days'),
    'ghost',      count(*) FILTER (WHERE ld.last_active IS NULL),
    'total',      count(*)
  ) INTO result
  FROM pubkeys p
  LEFT JOIN latest_device ld ON ld.pk = p.pk;

  RETURN result;
END;
$$;


--
-- Name: admin_add_timeline_event(date, text, text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_add_timeline_event(occurred_at date, label text, description text DEFAULT NULL::text, url text DEFAULT NULL::text) RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  new_id uuid;
  caller_pubkey text;
begin
  if not public.is_admin() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  if occurred_at is null then
    raise exception 'occurred_at required' using errcode = '22023';
  end if;
  if label is null or length(trim(label)) = 0 then
    raise exception 'label required' using errcode = '22023';
  end if;

  -- Best-effort: pull the calling admin's pubkey from the JWT so we can
  -- track who added what. Falls back to null if absent.
  caller_pubkey := nullif(
    (auth.jwt() -> 'user_metadata' ->> 'pubkey'),
    ''
  );

  insert into public.timeline_events (occurred_at, label, description, url, created_by)
    values (
      occurred_at,
      trim(label),
      nullif(trim(description), ''),
      nullif(trim(url), ''),
      caller_pubkey
    )
    returning id into new_id;

  return new_id;
end;
$$;


--
-- Name: admin_add_timeline_event(timestamp with time zone, text, text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_add_timeline_event(occurred_at timestamp with time zone, label text, description text DEFAULT NULL::text, url text DEFAULT NULL::text) RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO ''
    AS $$
declare
  caller_pubkey text;
  new_id uuid;
begin
  -- Require the caller to be an admin.
  if not exists (
    select 1 from public.admin_pubkeys
     where pubkey = (auth.jwt() -> 'app_metadata' ->> 'pubkey')
  ) then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  if label is null or length(trim(label)) = 0 then
    raise exception 'label required' using errcode = '22023';
  end if;

  -- Use app_metadata (not user_metadata) — app_metadata is server-writable only.
  caller_pubkey := nullif(
    (auth.jwt() -> 'app_metadata' ->> 'pubkey'),
    ''
  );

  insert into public.timeline_events (occurred_at, label, description, url, created_by)
    values (
      occurred_at,
      trim(label),
      nullif(trim(description), ''),
      nullif(trim(url), ''),
      caller_pubkey
    )
    returning id into new_id;

  return new_id;
end;
$$;


--
-- Name: admin_adjust_storage(text, bigint); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_adjust_storage(target_pubkey text, delta_bytes bigint) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  INSERT INTO public.pubkey_quotas (user_pubkey, note_count, total_bytes, image_bytes, extra_storage_bytes, updated_at)
  VALUES (target_pubkey, 0, 0, 0, greatest(delta_bytes, 0), now())
  ON CONFLICT (user_pubkey) DO UPDATE
    SET extra_storage_bytes = greatest(public.pubkey_quotas.extra_storage_bytes + delta_bytes, 0),
        updated_at = now();
END;
$$;


--
-- Name: admin_ban_pubkey(text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_ban_pubkey(target_pubkey text, p_reason text DEFAULT NULL::text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  v_admin_pubkey text;
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  v_admin_pubkey := auth.jwt() -> 'app_metadata' ->> 'pubkey';

  INSERT INTO public.banned_pubkeys (pubkey, reason, banned_by)
  VALUES (target_pubkey, p_reason, v_admin_pubkey)
  ON CONFLICT (pubkey) DO UPDATE
    SET reason = EXCLUDED.reason, banned_at = now(), banned_by = EXCLUDED.banned_by;
END;
$$;


--
-- Name: admin_cohort_retention(integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_cohort_retention(p_weeks integer DEFAULT 12) RETURNS TABLE(cohort_week date, cohort_size integer, w0 integer, w1 integer, w2 integer, w3 integer, w4 integer, w5 integer, w6 integer, w7 integer, w8 integer)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  IF p_weeks < 1 THEN p_weeks := 1; END IF;
  IF p_weeks > 52 THEN p_weeks := 52; END IF;

  RETURN QUERY
  WITH cohorts AS (
    SELECT
      date_trunc('week', u.created_at)::date AS cw,
      (u.raw_app_meta_data ->> 'pubkey') AS pk
    FROM auth.users u
    WHERE (u.raw_app_meta_data ->> 'pubkey') IS NOT NULL
      AND u.created_at >= now() - (p_weeks * interval '1 week')
  ),
  activity AS (
    SELECT DISTINCT pubkey AS pk, date_trunc('week', last_seen_at)::date AS aw
    FROM public.devices
    WHERE last_seen_at >= now() - ((p_weeks + 9) * interval '1 week')
  )
  SELECT
    c.cw AS cohort_week,
    count(DISTINCT c.pk)::int AS cohort_size,
    count(DISTINCT CASE WHEN a.aw = c.cw THEN c.pk END)::int AS w0,
    count(DISTINCT CASE WHEN a.aw = (c.cw + interval '1 week')::date THEN c.pk END)::int AS w1,
    count(DISTINCT CASE WHEN a.aw = (c.cw + interval '2 weeks')::date THEN c.pk END)::int AS w2,
    count(DISTINCT CASE WHEN a.aw = (c.cw + interval '3 weeks')::date THEN c.pk END)::int AS w3,
    count(DISTINCT CASE WHEN a.aw = (c.cw + interval '4 weeks')::date THEN c.pk END)::int AS w4,
    count(DISTINCT CASE WHEN a.aw = (c.cw + interval '5 weeks')::date THEN c.pk END)::int AS w5,
    count(DISTINCT CASE WHEN a.aw = (c.cw + interval '6 weeks')::date THEN c.pk END)::int AS w6,
    count(DISTINCT CASE WHEN a.aw = (c.cw + interval '7 weeks')::date THEN c.pk END)::int AS w7,
    count(DISTINCT CASE WHEN a.aw = (c.cw + interval '8 weeks')::date THEN c.pk END)::int AS w8
  FROM cohorts c
  LEFT JOIN activity a ON a.pk = c.pk
  GROUP BY c.cw
  ORDER BY c.cw DESC;
END;
$$;


--
-- Name: admin_db_health(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_db_health() RETURNS jsonb
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  result jsonb;
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  SELECT jsonb_build_object(
    'db_size',             pg_database_size(current_database()),
    'notes_table_size',    pg_total_relation_size('public.notes'),
    'notes_index_size',    pg_indexes_size('public.notes'),
    'devices_table_size',  pg_total_relation_size('public.devices'),
    'quotas_table_size',   pg_total_relation_size('public.pubkey_quotas'),
    'versions_table_size', CASE
      WHEN to_regclass('public.note_versions') IS NOT NULL
      THEN pg_total_relation_size('public.note_versions')
      ELSE 0
    END,
    'cache_table_size',    pg_total_relation_size('public.admin_cache'),
    'auth_users_count',    (SELECT count(*) FROM auth.users)
  ) INTO result;

  RETURN result;
END;
$$;


--
-- Name: admin_delete_timeline_event(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_delete_timeline_event(target_id uuid) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if not public.is_admin() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  delete from public.timeline_events where id = target_id;
end;
$$;


--
-- Name: admin_device_names_breakdown(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_device_names_breakdown() RETURNS TABLE(device_name text, total bigint, active_30d bigint)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  RETURN QUERY
  SELECT
    d.device_name,
    count(*)::bigint AS total,
    count(*) FILTER (WHERE d.last_seen_at > now() - interval '30 days')::bigint AS active_30d
  FROM public.devices d
  GROUP BY d.device_name
  ORDER BY total DESC;
END;
$$;


--
-- Name: admin_events_summary(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_events_summary() RETURNS TABLE(type text, source text, count bigint)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if not public.is_admin() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  return query
  select e.type, e.source, count(*)::bigint
  from public.admin_events e
  group by e.type, e.source
  order by e.type, count(*) desc;
end;
$$;


--
-- Name: admin_feature_adoption(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_feature_adoption() RETURNS jsonb
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  result jsonb;
  v_multi_device bigint := 0;
  v_history_users bigint := 0;
  v_image_users bigint := 0;
  v_burn_users bigint := 0;
  v_total_users bigint := 0;
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  SELECT count(DISTINCT (raw_app_meta_data ->> 'pubkey'))
  INTO v_total_users
  FROM auth.users
  WHERE (raw_app_meta_data ->> 'pubkey') IS NOT NULL;

  -- Multi-device users
  SELECT count(*) INTO v_multi_device
  FROM (SELECT pubkey FROM public.devices GROUP BY pubkey HAVING count(*) > 1) sub;

  -- Note history users (Pro feature)
  IF to_regclass('public.note_versions') IS NOT NULL THEN
    EXECUTE 'SELECT count(DISTINCT n.user_pubkey) FROM public.note_versions nv JOIN public.notes n ON n.id = nv.note_id'
    INTO v_history_users;
  END IF;

  -- Image users
  SELECT count(*) INTO v_image_users
  FROM public.pubkey_quotas WHERE image_bytes > 0;

  -- Burn note users
  IF to_regclass('public.burn_notes') IS NOT NULL THEN
    EXECUTE 'SELECT count(DISTINCT user_pubkey) FROM public.burn_notes'
    INTO v_burn_users;
  END IF;

  SELECT jsonb_build_object(
    'total_users',    v_total_users,
    'multi_device',   v_multi_device,
    'note_history',   v_history_users,
    'images',         v_image_users,
    'burn_notes',     v_burn_users
  ) INTO result;

  RETURN result;
END;
$$;


--
-- Name: admin_force_refresh_cache(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_force_refresh_cache() RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  PERFORM public.admin_refresh_cache();
END;
$$;


--
-- Name: admin_fp_anomalies(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_fp_anomalies() RETURNS TABLE(pubkey text, anomaly_type text, device_count bigint, detail text, is_pro boolean)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  -- Duplicate fingerprints: multiple active devices with identical
  -- (platform, gpu, cores) hashes for the same pubkey. Should not
  -- happen after dedup — indicates a bug or manipulation.
  RETURN QUERY
  SELECT
    d.pubkey,
    'duplicate_fingerprint'::text AS anomaly_type,
    count(*)::bigint AS device_count,
    'duplicate device fingerprint detected'::text AS detail,
    EXISTS(SELECT 1 FROM pro_pubkeys pp WHERE pp.pubkey = d.pubkey) AS is_pro
  FROM public.devices d
  WHERE d.revoked_at IS NULL
    AND d.fp_platform_hash IS NOT NULL
  GROUP BY d.pubkey, d.fp_platform_hash, d.fp_gpu_hash, d.fp_cores_hash
  HAVING count(*) > 1;

  -- Null GPU hash: WebGL blocked (Brave, restricted modes) or bot.
  -- Only flag if multiple devices on the same pubkey lack GPU data.
  RETURN QUERY
  SELECT
    d.pubkey,
    'null_gpu'::text AS anomaly_type,
    count(*)::bigint AS device_count,
    'GPU unavailable on ' || count(*)::text || ' device(s)' AS detail,
    EXISTS(SELECT 1 FROM pro_pubkeys pp WHERE pp.pubkey = d.pubkey) AS is_pro
  FROM public.devices d
  WHERE d.revoked_at IS NULL
    AND d.fp_platform_hash IS NOT NULL
    AND d.fp_gpu_hash IS NULL
  GROUP BY d.pubkey
  HAVING count(*) >= 2;
END;
$$;


--
-- Name: admin_get_cached(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_get_cached(p_key text) RETURNS jsonb
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  v_result jsonb;
  v_age interval;
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  SELECT payload, now() - computed_at
    INTO v_result, v_age
    FROM public.admin_cache
   WHERE key = p_key;

  -- Return null if missing or older than 12 hours (2x the refresh interval).
  IF v_result IS NULL OR v_age > interval '12 hours' THEN
    RETURN NULL;
  END IF;

  RETURN v_result;
END;
$$;


--
-- Name: admin_list_admins(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_list_admins() RETURNS TABLE(pubkey text, label text, created_at timestamp with time zone)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if not public.is_admin() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  return query
    select a.pubkey, a.label, a.created_at
      from public.admin_pubkeys a
     order by a.created_at asc;
end;
$$;


--
-- Name: admin_list_banned(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_list_banned() RETURNS TABLE(pubkey text, reason text, banned_at timestamp with time zone, banned_by text)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  RETURN QUERY
  SELECT bp.pubkey, bp.reason, bp.banned_at, bp.banned_by
  FROM public.banned_pubkeys bp
  ORDER BY bp.banned_at DESC;
END;
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: devices; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.devices (
    pubkey text NOT NULL,
    device_id text NOT NULL,
    device_name text DEFAULT 'Unknown device'::text NOT NULL,
    platform text DEFAULT 'web'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    device_group text,
    fp_platform_hash text,
    fp_gpu_hash text,
    fp_cores_hash text,
    fp_language_hash text
);


--
-- Name: COLUMN devices.device_group; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.devices.device_group IS 'Groups browser installs on the same physical device. Limit check counts DISTINCT device_group values. NULL = own slot.';


--
-- Name: COLUMN devices.fp_platform_hash; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.devices.fp_platform_hash IS 'HMAC-SHA256(fp_pepper, "platform:" || normalized_os). Pepper is per-user, derived from the BIP-39 seed. Server cannot reverse or cross-user-correlate.';


--
-- Name: COLUMN devices.fp_gpu_hash; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.devices.fp_gpu_hash IS 'HMAC-SHA256(fp_pepper, "gpu:" || webgl_renderer). NULL when GPU is unavailable (Brave, restricted contexts) so the server can apply the degraded matching threshold.';


--
-- Name: COLUMN devices.fp_cores_hash; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.devices.fp_cores_hash IS 'HMAC-SHA256(fp_pepper, "cores:" || navigator.hardwareConcurrency).';


--
-- Name: COLUMN devices.fp_language_hash; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.devices.fp_language_hash IS 'HMAC-SHA256(fp_pepper, "language:" || navigator.language).';


--
-- Name: admin_list_devices_for_pubkey(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_list_devices_for_pubkey(target_pubkey text) RETURNS SETOF public.devices
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if not public.is_admin() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  return query
    select *
      from public.devices
     where pubkey = target_pubkey
     order by last_seen_at desc;
end;
$$;


--
-- Name: admin_list_pro_users(integer, integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_list_pro_users(p_page integer DEFAULT 0, p_per_page integer DEFAULT 20) RETURNS TABLE(pubkey text, source text, amount_cents integer, created_at timestamp with time zone)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  IF p_per_page < 1 THEN p_per_page := 1; END IF;
  IF p_per_page > 100 THEN p_per_page := 100; END IF;
  IF p_page < 0 THEN p_page := 0; END IF;

  RETURN QUERY
  SELECT pp.pubkey, pp.source, pp.amount_cents, pp.created_at
  FROM public.pro_pubkeys pp
  ORDER BY pp.created_at DESC
  LIMIT p_per_page OFFSET (p_page * p_per_page);
END;
$$;


--
-- Name: admin_list_timeline_events(integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_list_timeline_events(days integer DEFAULT NULL::integer) RETURNS TABLE(id uuid, occurred_at date, label text, description text, url text, created_at timestamp with time zone)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if not public.is_admin() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  return query
    select t.id, t.occurred_at, t.label, t.description, t.url, t.created_at
      from public.timeline_events t
     where days is null
        or t.occurred_at >= (current_date - (days || ' days')::interval)::date
     order by t.occurred_at asc, t.created_at asc;
end;
$$;


--
-- Name: admin_notes_distribution(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_notes_distribution() RETURNS TABLE(bucket text, user_count bigint)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  RETURN QUERY
  WITH user_counts AS (
    SELECT note_count AS cnt FROM public.pubkey_quotas
  )
  SELECT
    CASE
      WHEN cnt = 0 THEN '0'
      WHEN cnt BETWEEN 1 AND 5 THEN '1-5'
      WHEN cnt BETWEEN 6 AND 20 THEN '6-20'
      WHEN cnt BETWEEN 21 AND 50 THEN '21-50'
      WHEN cnt BETWEEN 51 AND 100 THEN '51-100'
      WHEN cnt BETWEEN 101 AND 500 THEN '101-500'
      ELSE '500+'
    END AS bucket,
    count(*)::bigint AS user_count
  FROM user_counts
  GROUP BY 1
  ORDER BY min(cnt);
END;
$$;


--
-- Name: admin_platform_breakdown(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_platform_breakdown() RETURNS TABLE(platform text, total bigint, active_30d bigint)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  RETURN QUERY
  SELECT
    d.platform,
    count(*)::bigint AS total,
    count(*) FILTER (WHERE d.last_seen_at > now() - interval '30 days')::bigint AS active_30d
  FROM public.devices d
  GROUP BY d.platform
  ORDER BY total DESC;
END;
$$;


--
-- Name: admin_refresh_cache(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_refresh_cache() RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  BEGIN
    INSERT INTO admin_cache (key, payload, computed_at)
    VALUES ('overview', admin_stats_overview_v2(), now())
    ON CONFLICT (key) DO UPDATE SET payload = EXCLUDED.payload, computed_at = now();
  EXCEPTION WHEN OTHERS THEN NULL;
  END;

  BEGIN
    INSERT INTO admin_cache (key, payload, computed_at)
    VALUES ('cohort_retention',
      (SELECT coalesce(jsonb_agg(row_to_json(r)::jsonb), '[]'::jsonb) FROM admin_cohort_retention(12) r),
      now())
    ON CONFLICT (key) DO UPDATE SET payload = EXCLUDED.payload, computed_at = now();
  EXCEPTION WHEN OTHERS THEN NULL;
  END;

  BEGIN
    INSERT INTO admin_cache (key, payload, computed_at)
    VALUES ('activity_breakdown', admin_activity_breakdown(), now())
    ON CONFLICT (key) DO UPDATE SET payload = EXCLUDED.payload, computed_at = now();
  EXCEPTION WHEN OTHERS THEN NULL;
  END;

  BEGIN
    INSERT INTO admin_cache (key, payload, computed_at)
    VALUES ('activation_funnel', admin_activation_funnel(), now())
    ON CONFLICT (key) DO UPDATE SET payload = EXCLUDED.payload, computed_at = now();
  EXCEPTION WHEN OTHERS THEN NULL;
  END;

  BEGIN
    INSERT INTO admin_cache (key, payload, computed_at)
    VALUES ('notes_distribution',
      (SELECT coalesce(jsonb_agg(row_to_json(r)::jsonb), '[]'::jsonb) FROM admin_notes_distribution() r),
      now())
    ON CONFLICT (key) DO UPDATE SET payload = EXCLUDED.payload, computed_at = now();
  EXCEPTION WHEN OTHERS THEN NULL;
  END;

  BEGIN
    INSERT INTO admin_cache (key, payload, computed_at)
    VALUES ('storage_distribution',
      (SELECT coalesce(jsonb_agg(row_to_json(r)::jsonb), '[]'::jsonb) FROM admin_storage_distribution() r),
      now())
    ON CONFLICT (key) DO UPDATE SET payload = EXCLUDED.payload, computed_at = now();
  EXCEPTION WHEN OTHERS THEN NULL;
  END;

  BEGIN
    INSERT INTO admin_cache (key, payload, computed_at)
    VALUES ('platform_breakdown',
      (SELECT coalesce(jsonb_agg(row_to_json(r)::jsonb), '[]'::jsonb) FROM admin_platform_breakdown() r),
      now())
    ON CONFLICT (key) DO UPDATE SET payload = EXCLUDED.payload, computed_at = now();
  EXCEPTION WHEN OTHERS THEN NULL;
  END;

  BEGIN
    INSERT INTO admin_cache (key, payload, computed_at)
    VALUES ('feature_adoption', admin_feature_adoption(), now())
    ON CONFLICT (key) DO UPDATE SET payload = EXCLUDED.payload, computed_at = now();
  EXCEPTION WHEN OTHERS THEN NULL;
  END;

  BEGIN
    INSERT INTO admin_cache (key, payload, computed_at)
    VALUES ('db_health', admin_db_health(), now())
    ON CONFLICT (key) DO UPDATE SET payload = EXCLUDED.payload, computed_at = now();
  EXCEPTION WHEN OTHERS THEN NULL;
  END;

  BEGIN
    INSERT INTO admin_cache (key, payload, computed_at)
    VALUES ('fp_anomalies',
      (SELECT coalesce(jsonb_agg(row_to_json(r)::jsonb), '[]'::jsonb) FROM admin_fp_anomalies() r),
      now())
    ON CONFLICT (key) DO UPDATE SET payload = EXCLUDED.payload, computed_at = now();
  EXCEPTION WHEN OTHERS THEN NULL;
  END;
END;
$$;


--
-- Name: admin_revenue_overview(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_revenue_overview() RETURNS jsonb
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  result jsonb;
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  SELECT jsonb_build_object(
    'pro_total',              (SELECT count(*) FROM public.pro_pubkeys),
    'revenue_cents',          (SELECT coalesce(sum(amount_cents), 0) FROM public.pro_pubkeys),
    'early_supporters',       (SELECT count(*) FROM public.pro_pubkeys WHERE amount_cents IS NOT NULL AND amount_cents < 4800),
    'early_supporters_remaining', (490 - (SELECT count(*) FROM public.pro_pubkeys WHERE amount_cents IS NOT NULL AND amount_cents < 4800)),
    'avg_order_cents',        (SELECT coalesce(avg(amount_cents), 0)::int FROM public.pro_pubkeys WHERE amount_cents IS NOT NULL),
    'last_purchase_at',       (SELECT max(created_at) FROM public.pro_pubkeys),
    'manual_grants',          (SELECT count(*) FROM public.pro_pubkeys WHERE source = 'admin')
  ) INTO result;

  RETURN result;
END;
$$;


--
-- Name: admin_revoke_device(text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_revoke_device(target_pubkey text, target_device_id text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  DELETE FROM public.devices
  WHERE pubkey = target_pubkey AND device_id = target_device_id;
END;
$$;


--
-- Name: admin_set_admin(text, boolean, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_set_admin(target_pubkey text, make_admin boolean, label text DEFAULT NULL::text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  remaining int;
begin
  if not public.is_admin() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  if target_pubkey is null or length(target_pubkey) = 0 then
    raise exception 'target_pubkey required' using errcode = '22023';
  end if;

  if make_admin then
    insert into public.admin_pubkeys (pubkey, label)
      values (target_pubkey, label)
      on conflict (pubkey) do update
        set label = coalesce(excluded.label, public.admin_pubkeys.label);
  else
    -- Block removing the final admin. Count the rows that would remain
    -- after the delete; refuse if that's zero.
    select count(*)::int
      into remaining
      from public.admin_pubkeys
     where pubkey <> target_pubkey;

    if remaining = 0 then
      raise exception 'cannot remove the last admin'
        using errcode = '22023';
    end if;

    delete from public.admin_pubkeys where pubkey = target_pubkey;
  end if;
end;
$$;


--
-- Name: admin_set_pro(text, boolean); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_set_pro(target_pubkey text, make_pro boolean) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if not public.is_admin() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  if make_pro then
    insert into public.pro_pubkeys (pubkey, source, note)
      values (target_pubkey, 'admin', 'toggled via admin panel')
      on conflict (pubkey) do nothing;
  else
    delete from public.pro_pubkeys where pubkey = target_pubkey;
  end if;
end;
$$;


--
-- Name: admin_stats_daily_metrics(integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_stats_daily_metrics(days integer DEFAULT 30) RETURNS TABLE(day date, users_total bigint, active_7d bigint, notes_total bigint, pro_users bigint)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public', 'auth'
    AS $$
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  RETURN QUERY
  WITH ds AS (
    SELECT generate_series(
      (now()::date - (days - 1) * interval '1 day')::date,
      now()::date,
      interval '1 day'
    )::date AS d
  )
  SELECT
    ds.d AS day,
    (
      SELECT count(*)::bigint
      FROM auth.users u
      WHERE u.created_at::date <= ds.d
        AND (u.raw_app_meta_data ->> 'pubkey') IS NOT NULL
    ) AS users_total,
    (
      SELECT count(DISTINCT dv.pubkey)::bigint
      FROM public.devices dv
      WHERE dv.last_seen_at::date BETWEEN ds.d - interval '7 days' AND ds.d
    ) AS active_7d,
    (
      SELECT count(*)::bigint
      FROM public.notes n
      WHERE n.created_at::date <= ds.d
    ) AS notes_total,
    (
      SELECT count(*)::bigint
      FROM public.pro_pubkeys pp
      WHERE pp.created_at::date <= ds.d
    ) AS pro_users
  FROM ds
  ORDER BY ds.d;
END;
$$;


--
-- Name: admin_stats_overview(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_stats_overview() RETURNS json
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  result json;
begin
  if not public.is_admin() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  select json_build_object(
    'users_total',          (select count(*) from auth.users),
    'users_last_7d',        (select count(*) from auth.users where created_at > now() - interval '7 days'),
    'users_last_30d',       (select count(*) from auth.users where created_at > now() - interval '30 days'),
    'notes_total',          (select count(*) from public.notes),
    'notes_bytes_total',    (select coalesce(sum(octet_length(ciphertext)), 0)::bigint from public.notes),
    'user_settings_total',  (select count(*) from public.user_settings),
    'events_total',         (select count(*) from public.admin_events),
    'events_last_7d',       (select count(*) from public.admin_events where created_at > now() - interval '7 days'),
    'avg_notes_per_user',   (
      select case
        when (select count(*) from auth.users) = 0 then 0
        else round(
          (select count(*) from public.notes)::numeric
          / (select count(*) from auth.users)::numeric,
          2
        )
      end
    )
  ) into result;

  return result;
end;
$$;


--
-- Name: admin_stats_overview_v2(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_stats_overview_v2() RETURNS jsonb
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  result jsonb;
  v_user_settings_count bigint := 0;
  v_note_versions_count bigint := 0;
  v_burn_notes_count bigint := 0;
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  IF to_regclass('public.user_settings') IS NOT NULL THEN
    EXECUTE 'SELECT count(*) FROM public.user_settings' INTO v_user_settings_count;
  END IF;

  IF to_regclass('public.note_versions') IS NOT NULL THEN
    EXECUTE 'SELECT count(*) FROM public.note_versions' INTO v_note_versions_count;
  END IF;

  IF to_regclass('public.burn_notes') IS NOT NULL THEN
    EXECUTE 'SELECT count(*) FROM public.burn_notes' INTO v_burn_notes_count;
  END IF;

  SELECT jsonb_build_object(
    'users_total',          (SELECT count(*) FROM auth.users),
    'users_last_7d',        (SELECT count(*) FROM auth.users WHERE created_at > now() - interval '7 days'),
    'users_last_30d',       (SELECT count(*) FROM auth.users WHERE created_at > now() - interval '30 days'),
    'active_7d',            (SELECT count(DISTINCT pubkey) FROM public.devices WHERE last_seen_at > now() - interval '7 days'),
    'active_30d',           (SELECT count(DISTINCT pubkey) FROM public.devices WHERE last_seen_at > now() - interval '30 days'),
    'notes_total',          (SELECT count(*) FROM public.notes),
    'notes_bytes_total',    (SELECT coalesce(sum(total_bytes), 0)::bigint FROM public.pubkey_quotas),
    'image_bytes_total',    (SELECT coalesce(sum(image_bytes), 0)::bigint FROM public.pubkey_quotas),
    'avg_notes_per_user',   (
      SELECT CASE
        WHEN (SELECT count(*) FROM auth.users) = 0 THEN 0
        ELSE round(
          (SELECT count(*) FROM public.notes)::numeric
          / (SELECT count(*) FROM auth.users)::numeric, 2
        )
      END
    ),
    'pro_users',            (SELECT count(*) FROM public.pro_pubkeys),
    'revenue_cents',        (SELECT coalesce(sum(amount_cents), 0) FROM public.pro_pubkeys),
    'devices_total',        (SELECT count(*) FROM public.devices),
    'note_versions_total',  v_note_versions_count,
    'burn_notes_total',     v_burn_notes_count,
    'user_settings_total',  v_user_settings_count,
    'events_total',         (SELECT count(*) FROM public.admin_events),
    'events_last_7d',       (SELECT count(*) FROM public.admin_events WHERE created_at > now() - interval '7 days'),
    'banned_count',         (SELECT count(*) FROM public.banned_pubkeys),
    'db_size_bytes',        (SELECT pg_database_size(current_database()))
  ) INTO result;

  RETURN result;
END;
$$;


--
-- Name: admin_stats_signups_daily(integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_stats_signups_daily(days integer DEFAULT 30) RETURNS TABLE(day date, signups bigint)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
begin
  if not public.is_admin() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  -- Clamp the window so a caller can't ask for a 10-year scan.
  if days < 1  then days := 1;  end if;
  if days > 365 then days := 365; end if;

  return query
  select d::date as day,
         coalesce(count(u.id), 0) as signups
  from generate_series(
    (now()::date - (days - 1)),
    now()::date,
    interval '1 day'
  ) as d
  left join auth.users u
    on u.created_at::date = d::date
  group by d
  order by d;
end;
$$;


--
-- Name: admin_storage_distribution(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_storage_distribution() RETURNS TABLE(tier text, bucket text, user_count bigint)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  RETURN QUERY
  WITH usage AS (
    SELECT
      pq.user_pubkey,
      CASE WHEN pp.pubkey IS NOT NULL THEN 'pro' ELSE 'free' END AS tier,
      (pq.total_bytes + pq.image_bytes)::float /
        NULLIF(
          CASE WHEN pp.pubkey IS NOT NULL
            THEN (500 * 1024 * 1024 + pq.extra_storage_bytes)
            ELSE (50 * 1024 * 1024)
          END, 0
        ) AS pct
    FROM public.pubkey_quotas pq
    LEFT JOIN public.pro_pubkeys pp ON pp.pubkey = pq.user_pubkey
  )
  SELECT
    u.tier,
    CASE
      WHEN u.pct <= 0.10 THEN '0-10%'
      WHEN u.pct <= 0.25 THEN '10-25%'
      WHEN u.pct <= 0.50 THEN '25-50%'
      WHEN u.pct <= 0.75 THEN '50-75%'
      WHEN u.pct <= 0.90 THEN '75-90%'
      WHEN u.pct <= 1.00 THEN '90-100%'
      ELSE 'over'
    END AS bucket,
    count(*)::bigint AS user_count
  FROM usage u
  GROUP BY u.tier, 2
  ORDER BY u.tier, min(u.pct);
END;
$$;


--
-- Name: admin_unban_pubkey(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_unban_pubkey(target_pubkey text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  DELETE FROM public.banned_pubkeys WHERE pubkey = target_pubkey;
END;
$$;


--
-- Name: admin_user_lookup(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.admin_user_lookup(target_pubkey text) RETURNS jsonb
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $_$
DECLARE
  result jsonb;
  v_user_id uuid;
  v_created_at timestamptz;
  v_is_pro boolean;
  v_pro_row record;
  v_quota record;
  v_device_count int;
  v_last_active timestamptz;
  v_version_count bigint := 0;
  v_is_banned boolean;
  v_ban_reason text;
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'not authorized' USING errcode = '42501';
  END IF;

  -- Find the auth.users row
  SELECT id, created_at INTO v_user_id, v_created_at
  FROM auth.users
  WHERE (raw_app_meta_data ->> 'pubkey') = target_pubkey
  LIMIT 1;

  -- Pro status
  SELECT EXISTS(SELECT 1 FROM public.pro_pubkeys WHERE pubkey = target_pubkey) INTO v_is_pro;

  SELECT pp.source, pp.amount_cents, pp.created_at
  INTO v_pro_row
  FROM public.pro_pubkeys pp
  WHERE pp.pubkey = target_pubkey;

  -- Quota
  SELECT pq.note_count, pq.total_bytes, pq.image_bytes, pq.extra_storage_bytes
  INTO v_quota
  FROM public.pubkey_quotas pq
  WHERE pq.user_pubkey = target_pubkey;

  -- Devices
  SELECT count(*), max(last_seen_at)
  INTO v_device_count, v_last_active
  FROM public.devices
  WHERE pubkey = target_pubkey;

  -- Note versions
  IF to_regclass('public.note_versions') IS NOT NULL THEN
    EXECUTE 'SELECT count(*) FROM public.note_versions nv JOIN public.notes n ON n.id = nv.note_id WHERE n.user_pubkey = $1'
    INTO v_version_count USING target_pubkey;
  END IF;

  -- Ban status
  SELECT EXISTS(SELECT 1 FROM public.banned_pubkeys WHERE pubkey = target_pubkey) INTO v_is_banned;
  SELECT reason INTO v_ban_reason FROM public.banned_pubkeys WHERE pubkey = target_pubkey;

  SELECT jsonb_build_object(
    'found',              (v_user_id IS NOT NULL),
    'user_id',            v_user_id,
    'created_at',         v_created_at,
    'is_pro',             v_is_pro,
    'pro_source',         v_pro_row.source,
    'pro_amount_cents',   v_pro_row.amount_cents,
    'pro_since',          v_pro_row.created_at,
    'note_count',         coalesce(v_quota.note_count, 0),
    'total_bytes',        coalesce(v_quota.total_bytes, 0),
    'image_bytes',        coalesce(v_quota.image_bytes, 0),
    'extra_storage_bytes', coalesce(v_quota.extra_storage_bytes, 0),
    'device_count',       coalesce(v_device_count, 0),
    'last_active',        v_last_active,
    'days_since_active',  CASE WHEN v_last_active IS NOT NULL THEN extract(day FROM now() - v_last_active)::int ELSE NULL END,
    'note_versions',      v_version_count,
    'is_banned',          v_is_banned,
    'ban_reason',         v_ban_reason
  ) INTO result;

  RETURN result;
END;
$_$;


--
-- Name: block_writes_to_deleted_notes(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.block_writes_to_deleted_notes() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'public'
    AS $$
BEGIN
  IF OLD.deleted_at IS NOT NULL THEN
    -- Allow only the explicit hard-delete path (handled by DELETE,
    -- not UPDATE) and the no-op self-update where deleted_at stays.
    -- Anything else: silently drop.
    RETURN NULL;
  END IF;
  RETURN NEW;
END;
$$;


--
-- Name: burn_note_exists(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.burn_note_exists(p_id uuid) RETURNS boolean
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO ''
    AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 FROM public.burn_notes WHERE id = p_id
  );
END;
$$;


--
-- Name: FUNCTION burn_note_exists(p_id uuid); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.burn_note_exists(p_id uuid) IS 'Returns true if a burn note with the given id exists. Single-ID lookup only — no enumeration surface. Used by the client to decide whether to render the sealed UI on a /burn link.';


--
-- Name: check_and_set_quota_exceeded(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.check_and_set_quota_exceeded(p_pubkey text) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO ''
    AS $$
DECLARE
  v_used bigint;
  v_max bigint;
  v_currently_exceeded boolean;
  v_is_over boolean;
BEGIN
  -- Get current usage (total_bytes + image_bytes).
  SELECT COALESCE(pq.total_bytes, 0) + COALESCE(pq.image_bytes, 0),
         pq.quota_exceeded_since IS NOT NULL
    INTO v_used, v_currently_exceeded
    FROM public.pubkey_quotas pq
   WHERE pq.user_pubkey = p_pubkey;

  IF NOT FOUND THEN
    RETURN false;
  END IF;

  -- Get current cap.
  SELECT max_total_bytes INTO v_max
    FROM public.quota_limits_for_pubkey(p_pubkey);

  v_is_over := v_used > v_max;

  IF v_is_over AND NOT v_currently_exceeded THEN
    -- Just went over — start the clock.
    UPDATE public.pubkey_quotas
       SET quota_exceeded_since = now(),
           updated_at = now()
     WHERE user_pubkey = p_pubkey;
  ELSIF NOT v_is_over AND v_currently_exceeded THEN
    -- Back under — clear the flag.
    UPDATE public.pubkey_quotas
       SET quota_exceeded_since = NULL,
           updated_at = now()
     WHERE user_pubkey = p_pubkey;
  END IF;

  RETURN v_is_over;
END;
$$;


--
-- Name: consume_burn_note(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.consume_burn_note(note_id uuid) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO ''
    AS $$
declare
  result text;
begin
  delete from public.burn_notes
  where id = note_id
  returning ciphertext into result;
  return result;
end;
$$;


--
-- Name: count_device_slots(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.count_device_slots(p_pubkey text) RETURNS integer
    LANGUAGE sql STABLE SECURITY DEFINER
    AS $$
  SELECT COUNT(*)::integer FROM (
    SELECT DISTINCT COALESCE(device_group, device_id) AS slot
    FROM devices
    WHERE pubkey = p_pubkey
      AND revoked_at IS NULL
  ) sub;
$$;


--
-- Name: device_heartbeat(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.device_heartbeat(p_device_id text) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
DECLARE
  v_pubkey  text;
  v_updated int;
BEGIN
  v_pubkey := auth.jwt() -> 'app_metadata' ->> 'pubkey';
  IF v_pubkey IS NULL OR v_pubkey = '' THEN
    RETURN false;
  END IF;

  -- Banned users get kicked on next heartbeat.
  IF EXISTS (SELECT 1 FROM public.banned_pubkeys WHERE pubkey = v_pubkey) THEN
    RETURN false;
  END IF;

  UPDATE public.devices
     SET last_seen_at = now()
   WHERE pubkey = v_pubkey
     AND device_id = p_device_id
     AND revoked_at IS NULL;

  GET DIAGNOSTICS v_updated = ROW_COUNT;
  RETURN v_updated > 0;
END;
$$;


--
-- Name: enforce_burn_note_rate_limit(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_burn_note_rate_limit() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO ''
    AS $$
DECLARE
  v_user_count integer;
BEGIN
  -- Per-user cap: 100 burn notes per hour. Generous enough to never
  -- frustrate real usage (team handoffs, onboarding), tight enough to
  -- slow a single-account spammer. user_id is auto-filled from JWT via
  -- column DEFAULT; NULL means unauthenticated — skip the check.
  IF NEW.user_id IS NOT NULL THEN
    SELECT count(*) INTO v_user_count
      FROM public.burn_notes
     WHERE user_id = NEW.user_id
       AND created_at > now() - interval '1 hour';

    IF v_user_count >= 100 THEN
      RAISE EXCEPTION 'Burn note rate limit exceeded — try again later'
        USING errcode = 'check_violation';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;


--
-- Name: FUNCTION enforce_burn_note_rate_limit(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.enforce_burn_note_rate_limit() IS 'Per-user rate limit: max 100 burn notes/hour. Primary abuse defense is Cloudflare IP rate-limits + 24h TTL purge.';


--
-- Name: enforce_notes_quota(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_notes_quota() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO ''
    AS $$

DECLARE

  v_max_notes integer;

  v_max_bytes bigint;

  v_delta_count integer := 0;

  v_delta_bytes bigint := 0;

  v_current_count integer;

  v_current_bytes bigint;

  v_pubkey text;

  v_exceeded_since timestamptz;

  v_is_tombstone boolean := false;

  v_is_restore boolean := false;

BEGIN

  v_pubkey := COALESCE(NEW.user_pubkey, OLD.user_pubkey);

  -- Detect soft-delete tombstone and restore transitions.

  IF (TG_OP = 'UPDATE') THEN

    v_is_tombstone := (NEW.deleted_at IS NOT NULL AND OLD.deleted_at IS NULL);

    v_is_restore := (NEW.deleted_at IS NULL AND OLD.deleted_at IS NOT NULL);

  END IF;

  -- Check for sync freeze (90-day grace period expired).

  -- Exempt tombstone UPDATEs so users can delete notes to recover.

  IF (TG_OP IN ('INSERT', 'UPDATE')) AND NOT v_is_tombstone THEN

    SELECT pq.quota_exceeded_since INTO v_exceeded_since

      FROM public.pubkey_quotas pq

     WHERE pq.user_pubkey = v_pubkey;

    IF v_exceeded_since IS NOT NULL

       AND v_exceeded_since < (now() - interval '90 days') THEN

      RAISE EXCEPTION 'Sync frozen: storage quota exceeded for more than 90 days. Re-subscribe or reduce usage.'

        USING errcode = 'check_violation';

    END IF;

  END IF;

  SELECT max_notes, max_total_bytes

    INTO v_max_notes, v_max_bytes

    FROM public.quota_limits_for_pubkey(v_pubkey);

  IF (TG_OP = 'INSERT') THEN

    v_delta_count := 1;

    v_delta_bytes := octet_length(NEW.ciphertext);

  ELSIF (TG_OP = 'UPDATE') THEN

    v_delta_count := 0;

    IF v_is_tombstone THEN

      -- Tombstone: free the space immediately so quota reflects the delete.

      v_delta_bytes := -octet_length(OLD.ciphertext);

    ELSIF v_is_restore THEN

      -- Restore: re-add the bytes (they were removed on tombstone).

      v_delta_bytes := octet_length(NEW.ciphertext);

    ELSE

      -- Normal edit: delta between old and new ciphertext.

      v_delta_bytes := octet_length(NEW.ciphertext) - octet_length(OLD.ciphertext);

    END IF;

  ELSIF (TG_OP = 'DELETE') THEN

    v_delta_count := -1;

    -- If the row was already tombstoned, bytes were decremented on tombstone.

    -- Only decrement bytes for hard-deletes of non-tombstoned rows.

    IF OLD.deleted_at IS NOT NULL THEN

      v_delta_bytes := 0;

    ELSE

      v_delta_bytes := -octet_length(OLD.ciphertext);

    END IF;

  END IF;

  INSERT INTO public.pubkey_quotas (user_pubkey, note_count, total_bytes, updated_at)

    VALUES (

      v_pubkey,

      greatest(0, v_delta_count),

      greatest(0, v_delta_bytes),

      now()

    )

  ON CONFLICT (user_pubkey) DO UPDATE

    SET note_count  = public.pubkey_quotas.note_count  + v_delta_count,

        total_bytes = public.pubkey_quotas.total_bytes + v_delta_bytes,

        updated_at  = now()

  RETURNING note_count, total_bytes INTO v_current_count, v_current_bytes;

  -- Skip quota cap checks for tombstones — user is trying to free space.

  IF (TG_OP IN ('INSERT', 'UPDATE')) AND NOT v_is_tombstone THEN

    IF v_current_count > v_max_notes THEN

      RAISE EXCEPTION 'Quota exceeded: note count % > limit %', v_current_count, v_max_notes

        USING errcode = 'check_violation';

    END IF;

    IF v_current_bytes > v_max_bytes THEN

      RAISE EXCEPTION 'Quota exceeded: total ciphertext % bytes > limit % bytes', v_current_bytes, v_max_bytes

        USING errcode = 'check_violation';

    END IF;

  END IF;

  -- After tombstone or restore, re-evaluate quota exceeded status so the

  -- client banner updates immediately instead of waiting for the next

  -- webhook or cron cycle.

  IF v_is_tombstone OR v_is_restore THEN

    PERFORM public.check_and_set_quota_exceeded(v_pubkey);

  END IF;

  IF (TG_OP = 'DELETE') THEN

    RETURN OLD;

  ELSE

    RETURN NEW;

  END IF;

END;

$$;


--
-- Name: get_my_quota_limits(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.get_my_quota_limits() RETURNS TABLE(max_notes integer, max_total_bytes bigint, max_image_bytes bigint)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO ''
    AS $$
DECLARE
  v_pubkey text;
BEGIN
  v_pubkey := auth.jwt() -> 'app_metadata' ->> 'pubkey';
  IF v_pubkey IS NULL THEN
    RAISE EXCEPTION 'pubkey not linked';
  END IF;

  RETURN QUERY SELECT * FROM public.quota_limits_for_pubkey(v_pubkey);
END;
$$;


--
-- Name: get_my_quota_status(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.get_my_quota_status() RETURNS TABLE(max_notes integer, max_total_bytes bigint, max_image_bytes bigint, quota_exceeded_since timestamp with time zone)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO ''
    AS $$
DECLARE
  v_pubkey text;
BEGIN
  v_pubkey := auth.jwt() -> 'app_metadata' ->> 'pubkey';
  IF v_pubkey IS NULL THEN
    RAISE EXCEPTION 'pubkey not linked';
  END IF;

  RETURN QUERY
    SELECT ql.max_notes, ql.max_total_bytes, ql.max_image_bytes, pq.quota_exceeded_since
      FROM public.quota_limits_for_pubkey(v_pubkey) ql
      LEFT JOIN public.pubkey_quotas pq ON pq.user_pubkey = v_pubkey;
END;
$$;


--
-- Name: get_storage_sub_status(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.get_storage_sub_status() RETURNS TABLE(has_past_due boolean, past_due_since timestamp with time zone, active_count integer, past_due_count integer)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO ''
    AS $$
DECLARE
  v_pubkey text;
  v_pd_count integer;
  v_active_count integer;
  v_earliest_pd timestamptz;
BEGIN
  v_pubkey := auth.jwt() -> 'app_metadata' ->> 'pubkey';
  IF v_pubkey IS NULL THEN
    RETURN QUERY SELECT false, NULL::timestamptz, 0, 0;
    RETURN;
  END IF;

  SELECT count(*)::integer INTO v_active_count
    FROM public.paddle_storage_subs
   WHERE pubkey = v_pubkey AND status = 'active' AND NOT gated;

  SELECT count(*)::integer, min(updated_at) INTO v_pd_count, v_earliest_pd
    FROM public.paddle_storage_subs
   WHERE pubkey = v_pubkey AND status = 'past_due' AND NOT gated;

  RETURN QUERY SELECT
    (v_pd_count > 0),
    v_earliest_pd,
    v_active_count,
    v_pd_count;
END;
$$;


--
-- Name: has_active_storage_sub(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.has_active_storage_sub() RETURNS boolean
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO ''
    AS $$
DECLARE
  v_pubkey text;
BEGIN
  v_pubkey := auth.jwt() -> 'app_metadata' ->> 'pubkey';
  IF v_pubkey IS NULL THEN RETURN false; END IF;

  RETURN EXISTS (
    SELECT 1 FROM public.paddle_storage_subs
     WHERE pubkey = v_pubkey
       AND status IN ('active','past_due')
       AND NOT gated
  );
END;
$$;


--
-- Name: is_admin(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.is_admin() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select exists (
    select 1
    from public.admin_pubkeys
    where pubkey = (auth.jwt() -> 'app_metadata' ->> 'pubkey')
  );
$$;


--
-- Name: is_pro(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.is_pro() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  select exists (
    select 1
    from public.pro_pubkeys
    where pubkey = (auth.jwt() -> 'app_metadata' ->> 'pubkey')
  );
$$;


--
-- Name: notes_quota_limits(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.notes_quota_limits() RETURNS TABLE(max_notes integer, max_bytes bigint)
    LANGUAGE sql IMMUTABLE
    SET search_path TO ''
    AS $$
  select 10000::integer as max_notes, (200 * 1024 * 1024)::bigint as max_bytes;
$$;


--
-- Name: prune_note_versions(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.prune_note_versions() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO ''
    AS $$
declare
  v_count int;
begin
  select count(*) into v_count
    from public.note_versions
    where note_id = new.note_id;

  if v_count >= 20 then
    delete from public.note_versions
     where id in (
       select id from public.note_versions
        where note_id = new.note_id
        order by created_at asc
        limit v_count - 19
     );
  end if;

  return new;
end;
$$;


--
-- Name: pubkey_has_active_storage_sub(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.pubkey_has_active_storage_sub(p_pubkey text) RETURNS boolean
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO ''
    AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 FROM public.paddle_storage_subs
     WHERE pubkey = p_pubkey
       AND status IN ('active','past_due')
       AND NOT gated
  );
END;
$$;


--
-- Name: purge_provisional_users(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.purge_provisional_users() RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO ''
    AS $$
DECLARE
  v_deleted integer;
BEGIN
  WITH victims AS (
    SELECT id
      FROM auth.users
     WHERE is_anonymous = true
       AND created_at < now() - interval '7 days'
       AND (raw_app_meta_data ->> 'pubkey') IS NULL
     LIMIT 50000
  )
  DELETE FROM auth.users u
   USING victims v
   WHERE u.id = v.id;
  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  RETURN v_deleted;
END;
$$;


--
-- Name: FUNCTION purge_provisional_users(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.purge_provisional_users() IS 'Deletes anonymous auth.users older than 7 days that never linked a pubkey. Runs nightly via pg_cron. Limit 50k per invocation.';


--
-- Name: quota_limits_for_pubkey(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.quota_limits_for_pubkey(p_pubkey text) RETURNS TABLE(max_notes integer, max_total_bytes bigint, max_image_bytes bigint)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO ''
    AS $$
DECLARE
  v_is_pro boolean;
  v_extra bigint;
BEGIN
  SELECT EXISTS (
    SELECT 1 FROM public.pro_pubkeys WHERE pubkey = p_pubkey
  ) INTO v_is_pro;

  SELECT COALESCE(SUM(gb_count) * 1073741824, 0)::bigint INTO v_extra
    FROM public.paddle_storage_subs
   WHERE pubkey = p_pubkey
     AND status IN ('active','past_due')
     AND NOT gated;

  IF v_is_pro THEN
    -- Pro: 500 MB base + purchased add-ons. Combined limit covers
    -- both notes and images.
    RETURN QUERY SELECT
      10000::integer,
      (500 * 1024 * 1024 + v_extra)::bigint,
      (500 * 1024 * 1024 + v_extra)::bigint;
  ELSE
    -- Free: 50 MB combined quota shared between notes and images.
    RETURN QUERY SELECT
      10000::integer,
      (50 * 1024 * 1024)::bigint,
      (50 * 1024 * 1024)::bigint;
  END IF;
END;
$$;


--
-- Name: rls_auto_enable(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.rls_auto_enable() RETURNS event_trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE
  cmd record;
BEGIN
  FOR cmd IN
    SELECT *
    FROM pg_event_trigger_ddl_commands()
    WHERE command_tag IN ('CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO')
      AND object_type IN ('table','partitioned table')
  LOOP
     IF cmd.schema_name IS NOT NULL AND cmd.schema_name IN ('public') AND cmd.schema_name NOT IN ('pg_catalog','information_schema') AND cmd.schema_name NOT LIKE 'pg_toast%' AND cmd.schema_name NOT LIKE 'pg_temp%' THEN
      BEGIN
        EXECUTE format('alter table if exists %s enable row level security', cmd.object_identity);
        RAISE LOG 'rls_auto_enable: enabled RLS on %', cmd.object_identity;
      EXCEPTION
        WHEN OTHERS THEN
          RAISE LOG 'rls_auto_enable: failed to enable RLS on %', cmd.object_identity;
      END;
     ELSE
        RAISE LOG 'rls_auto_enable: skip % (either system schema or not in enforced list: %.)', cmd.object_identity, cmd.schema_name;
     END IF;
  END LOOP;
END;
$$;


--
-- Name: set_storage_sub_status(text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.set_storage_sub_status(p_subscription_id text, p_status text) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO ''
    AS $$
DECLARE
  v_count integer;
BEGIN
  IF p_status NOT IN ('active','past_due','canceled') THEN
    RAISE EXCEPTION 'invalid status %', p_status;
  END IF;

  UPDATE public.paddle_storage_subs
     SET status      = p_status,
         canceled_at = CASE WHEN p_status = 'canceled' THEN now() ELSE canceled_at END,
         updated_at  = now()
   WHERE subscription_id = p_subscription_id;

  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END;
$$;


--
-- Name: upsert_storage_sub(text, text, text, integer, text, timestamp with time zone, boolean); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.upsert_storage_sub(p_subscription_id text, p_pubkey text, p_price_id text, p_gb_count integer, p_status text, p_started_at timestamp with time zone, p_gated boolean DEFAULT false) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO ''
    AS $$
BEGIN
  INSERT INTO public.paddle_storage_subs
    (subscription_id, pubkey, price_id, gb_count, status, started_at, gated, updated_at)
  VALUES
    (p_subscription_id, p_pubkey, p_price_id, p_gb_count, p_status, p_started_at, p_gated, now())
  ON CONFLICT (subscription_id) DO UPDATE
    SET status     = EXCLUDED.status,
        gb_count   = EXCLUDED.gb_count,
        gated      = EXCLUDED.gated,
        updated_at = now();
END;
$$;


--
-- Name: abuse_allowlist; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.abuse_allowlist (
    pubkey text NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    added_by_pubkey text,
    reason text
);


--
-- Name: admin_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_cache (
    key text NOT NULL,
    payload jsonb NOT NULL,
    computed_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: admin_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    type text NOT NULL,
    source text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: admin_pubkeys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_pubkeys (
    pubkey text NOT NULL,
    label text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: banned_pubkeys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.banned_pubkeys (
    pubkey text NOT NULL,
    reason text,
    banned_at timestamp with time zone DEFAULT now() NOT NULL,
    banned_by text NOT NULL
);


--
-- Name: burn_notes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.burn_notes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ciphertext text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    user_id uuid DEFAULT auth.uid(),
    CONSTRAINT burn_notes_ciphertext_max CHECK ((octet_length(ciphertext) <= 65536))
);


--
-- Name: note_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.note_versions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    note_id uuid NOT NULL,
    user_pubkey text NOT NULL,
    ciphertext text NOT NULL,
    nonce text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT note_versions_ciphertext_max_1mb CHECK ((octet_length(ciphertext) <= 1048576))
);


--
-- Name: TABLE note_versions; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.note_versions IS 'Encrypted per-note version history (Pro). Capped at 20 rows per note; oldest pruned on insert. Client throttles snapshots to one per 5 minutes per note on top of this cap. Ciphertext + nonce use the same xchacha20poly1305 key as the parent note.';


--
-- Name: notes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.notes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_pubkey text NOT NULL,
    ciphertext text NOT NULL,
    nonce text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    CONSTRAINT notes_ciphertext_max_1mb CHECK ((octet_length(ciphertext) <= 1048576))
);


--
-- Name: COLUMN notes.deleted_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.notes.deleted_at IS 'Soft-delete tombstone. NULL = live row. Set by client when user permanently deletes. Hard-deleted by pg_cron after 30 days.';


--
-- Name: paddle_storage_subs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.paddle_storage_subs (
    subscription_id text NOT NULL,
    pubkey text NOT NULL,
    price_id text NOT NULL,
    gb_count integer NOT NULL,
    status text NOT NULL,
    started_at timestamp with time zone NOT NULL,
    canceled_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    gated boolean DEFAULT false NOT NULL,
    CONSTRAINT paddle_storage_subs_gb_count_check CHECK ((gb_count > 0)),
    CONSTRAINT paddle_storage_subs_status_check CHECK ((status = ANY (ARRAY['active'::text, 'past_due'::text, 'canceled'::text])))
);


--
-- Name: TABLE paddle_storage_subs; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.paddle_storage_subs IS 'One row per Paddle storage subscription. Source of truth for purchased capacity. Updated by paddle-webhook.';


--
-- Name: COLUMN paddle_storage_subs.gated; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.paddle_storage_subs.gated IS 'True when the sub was created before the user had Pro. Capacity is not granted until Pro is purchased and gated is flipped to false.';


--
-- Name: pro_pubkeys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pro_pubkeys (
    pubkey text NOT NULL,
    source text DEFAULT 'manual'::text NOT NULL,
    amount_cents integer,
    note text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: pubkey_quotas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pubkey_quotas (
    user_pubkey text NOT NULL,
    note_count integer DEFAULT 0 NOT NULL,
    total_bytes bigint DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    image_bytes bigint DEFAULT 0 NOT NULL,
    quota_exceeded_since timestamp with time zone,
    CONSTRAINT pubkey_quotas_note_count_nonneg CHECK ((note_count >= 0)),
    CONSTRAINT pubkey_quotas_total_bytes_nonneg CHECK ((total_bytes >= 0))
);


--
-- Name: TABLE pubkey_quotas; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.pubkey_quotas IS 'Per-pubkey running totals maintained by notes trigger. Used to enforce abuse limits (note_count, total_bytes).';


--
-- Name: COLUMN pubkey_quotas.image_bytes; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.pubkey_quotas.image_bytes IS 'Running total of encrypted image blob bytes in Supabase Storage for this pubkey.';


--
-- Name: COLUMN pubkey_quotas.quota_exceeded_since; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.pubkey_quotas.quota_exceeded_since IS 'Set when user is over their storage cap (e.g. after storage sub cancels). NULL = within quota. Used for grace period + sync freeze.';


--
-- Name: timeline_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.timeline_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    occurred_at date NOT NULL,
    label text NOT NULL,
    description text,
    url text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by text,
    CONSTRAINT timeline_events_description_check CHECK (((description IS NULL) OR (length(description) <= 2000))),
    CONSTRAINT timeline_events_label_check CHECK (((length(label) >= 1) AND (length(label) <= 80))),
    CONSTRAINT timeline_events_url_check CHECK (((url IS NULL) OR (length(url) <= 2000)))
);


--
-- Name: user_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_settings (
    user_pubkey text NOT NULL,
    ciphertext text NOT NULL,
    nonce text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: abuse_allowlist abuse_allowlist_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.abuse_allowlist
    ADD CONSTRAINT abuse_allowlist_pkey PRIMARY KEY (pubkey);


--
-- Name: admin_cache admin_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_cache
    ADD CONSTRAINT admin_cache_pkey PRIMARY KEY (key);


--
-- Name: admin_events admin_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_events
    ADD CONSTRAINT admin_events_pkey PRIMARY KEY (id);


--
-- Name: admin_pubkeys admin_pubkeys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_pubkeys
    ADD CONSTRAINT admin_pubkeys_pkey PRIMARY KEY (pubkey);


--
-- Name: banned_pubkeys banned_pubkeys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.banned_pubkeys
    ADD CONSTRAINT banned_pubkeys_pkey PRIMARY KEY (pubkey);


--
-- Name: burn_notes burn_notes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.burn_notes
    ADD CONSTRAINT burn_notes_pkey PRIMARY KEY (id);


--
-- Name: devices devices_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.devices
    ADD CONSTRAINT devices_pkey PRIMARY KEY (pubkey, device_id);


--
-- Name: note_versions note_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.note_versions
    ADD CONSTRAINT note_versions_pkey PRIMARY KEY (id);


--
-- Name: notes notes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notes
    ADD CONSTRAINT notes_pkey PRIMARY KEY (id);


--
-- Name: paddle_storage_subs paddle_storage_subs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.paddle_storage_subs
    ADD CONSTRAINT paddle_storage_subs_pkey PRIMARY KEY (subscription_id);


--
-- Name: pro_pubkeys pro_pubkeys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pro_pubkeys
    ADD CONSTRAINT pro_pubkeys_pkey PRIMARY KEY (pubkey);


--
-- Name: pubkey_quotas pubkey_quotas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pubkey_quotas
    ADD CONSTRAINT pubkey_quotas_pkey PRIMARY KEY (user_pubkey);


--
-- Name: timeline_events timeline_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.timeline_events
    ADD CONSTRAINT timeline_events_pkey PRIMARY KEY (id);


--
-- Name: user_settings user_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_settings
    ADD CONSTRAINT user_settings_pkey PRIMARY KEY (user_pubkey);


--
-- Name: admin_events_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX admin_events_created_at_idx ON public.admin_events USING btree (created_at);


--
-- Name: admin_events_type_source_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX admin_events_type_source_idx ON public.admin_events USING btree (type, source);


--
-- Name: burn_notes_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX burn_notes_created_at_idx ON public.burn_notes USING btree (created_at);


--
-- Name: devices_last_seen_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX devices_last_seen_at_idx ON public.devices USING btree (last_seen_at);


--
-- Name: devices_pubkey_fp_platform_hash_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX devices_pubkey_fp_platform_hash_idx ON public.devices USING btree (pubkey, fp_platform_hash);


--
-- Name: devices_pubkey_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX devices_pubkey_idx ON public.devices USING btree (pubkey);


--
-- Name: devices_revoked_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX devices_revoked_at_idx ON public.devices USING btree (revoked_at) WHERE (revoked_at IS NOT NULL);


--
-- Name: note_versions_note_id_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX note_versions_note_id_created_at_idx ON public.note_versions USING btree (note_id, created_at DESC);


--
-- Name: note_versions_user_pubkey_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX note_versions_user_pubkey_idx ON public.note_versions USING btree (user_pubkey);


--
-- Name: notes_deleted_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX notes_deleted_at_idx ON public.notes USING btree (user_pubkey, deleted_at) WHERE (deleted_at IS NOT NULL);


--
-- Name: notes_updated_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX notes_updated_at_idx ON public.notes USING btree (updated_at);


--
-- Name: notes_user_pubkey_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX notes_user_pubkey_idx ON public.notes USING btree (user_pubkey);


--
-- Name: notes_user_pubkey_updated_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX notes_user_pubkey_updated_at_idx ON public.notes USING btree (user_pubkey, updated_at DESC);


--
-- Name: paddle_storage_subs_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX paddle_storage_subs_active_idx ON public.paddle_storage_subs USING btree (pubkey, status) WHERE (status = ANY (ARRAY['active'::text, 'past_due'::text]));


--
-- Name: paddle_storage_subs_pubkey_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX paddle_storage_subs_pubkey_idx ON public.paddle_storage_subs USING btree (pubkey);


--
-- Name: timeline_events_occurred_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX timeline_events_occurred_at_idx ON public.timeline_events USING btree (occurred_at DESC);


--
-- Name: user_settings_updated_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_settings_updated_at_idx ON public.user_settings USING btree (updated_at);


--
-- Name: burn_notes burn_notes_rate_limit; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER burn_notes_rate_limit BEFORE INSERT ON public.burn_notes FOR EACH ROW EXECUTE FUNCTION public.enforce_burn_note_rate_limit();


--
-- Name: note_versions note_versions_cap_20; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER note_versions_cap_20 BEFORE INSERT ON public.note_versions FOR EACH ROW EXECUTE FUNCTION public.prune_note_versions();


--
-- Name: notes notes_block_writes_to_deleted; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER notes_block_writes_to_deleted BEFORE UPDATE ON public.notes FOR EACH ROW EXECUTE FUNCTION public.block_writes_to_deleted_notes();


--
-- Name: notes notes_enforce_quota; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER notes_enforce_quota AFTER INSERT OR DELETE OR UPDATE ON public.notes FOR EACH ROW EXECUTE FUNCTION public.enforce_notes_quota();


--
-- Name: note_versions note_versions_note_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.note_versions
    ADD CONSTRAINT note_versions_note_id_fkey FOREIGN KEY (note_id) REFERENCES public.notes(id) ON DELETE CASCADE;


--
-- Name: abuse_allowlist; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.abuse_allowlist ENABLE ROW LEVEL SECURITY;

--
-- Name: abuse_allowlist abuse_allowlist_admin_delete; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY abuse_allowlist_admin_delete ON public.abuse_allowlist FOR DELETE USING (public.is_admin());


--
-- Name: abuse_allowlist abuse_allowlist_admin_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY abuse_allowlist_admin_insert ON public.abuse_allowlist FOR INSERT WITH CHECK (public.is_admin());


--
-- Name: abuse_allowlist abuse_allowlist_admin_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY abuse_allowlist_admin_select ON public.abuse_allowlist FOR SELECT USING (public.is_admin());


--
-- Name: admin_cache; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.admin_cache ENABLE ROW LEVEL SECURITY;

--
-- Name: admin_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.admin_events ENABLE ROW LEVEL SECURITY;

--
-- Name: admin_events admin_events_insert_known_types; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY admin_events_insert_known_types ON public.admin_events FOR INSERT TO authenticated WITH CHECK (((type = ANY (ARRAY['import'::text, 'export'::text])) AND (length(source) <= 32)));


--
-- Name: admin_pubkeys; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.admin_pubkeys ENABLE ROW LEVEL SECURITY;

--
-- Name: banned_pubkeys; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.banned_pubkeys ENABLE ROW LEVEL SECURITY;

--
-- Name: burn_notes; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.burn_notes ENABLE ROW LEVEL SECURITY;

--
-- Name: burn_notes burn_notes_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY burn_notes_insert ON public.burn_notes FOR INSERT TO authenticated, anon WITH CHECK (true);


--
-- Name: devices; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.devices ENABLE ROW LEVEL SECURITY;

--
-- Name: devices devices_owner_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY devices_owner_select ON public.devices FOR SELECT USING ((pubkey = ((auth.jwt() -> 'app_metadata'::text) ->> 'pubkey'::text)));


--
-- Name: note_versions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.note_versions ENABLE ROW LEVEL SECURITY;

--
-- Name: note_versions note_versions_owner_delete; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY note_versions_owner_delete ON public.note_versions FOR DELETE USING ((user_pubkey = ((auth.jwt() -> 'app_metadata'::text) ->> 'pubkey'::text)));


--
-- Name: note_versions note_versions_owner_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY note_versions_owner_insert ON public.note_versions FOR INSERT WITH CHECK (((user_pubkey = ((auth.jwt() -> 'app_metadata'::text) ->> 'pubkey'::text)) AND public.is_pro()));


--
-- Name: note_versions note_versions_owner_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY note_versions_owner_select ON public.note_versions FOR SELECT USING ((user_pubkey = ((auth.jwt() -> 'app_metadata'::text) ->> 'pubkey'::text)));


--
-- Name: notes; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;

--
-- Name: notes notes_owner_delete; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY notes_owner_delete ON public.notes FOR DELETE USING ((user_pubkey = ((auth.jwt() -> 'app_metadata'::text) ->> 'pubkey'::text)));


--
-- Name: notes notes_owner_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY notes_owner_insert ON public.notes FOR INSERT WITH CHECK ((user_pubkey = ((auth.jwt() -> 'app_metadata'::text) ->> 'pubkey'::text)));


--
-- Name: notes notes_owner_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY notes_owner_select ON public.notes FOR SELECT USING ((user_pubkey = ((auth.jwt() -> 'app_metadata'::text) ->> 'pubkey'::text)));


--
-- Name: notes notes_owner_update; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY notes_owner_update ON public.notes FOR UPDATE USING ((user_pubkey = ((auth.jwt() -> 'app_metadata'::text) ->> 'pubkey'::text))) WITH CHECK ((user_pubkey = ((auth.jwt() -> 'app_metadata'::text) ->> 'pubkey'::text)));


--
-- Name: paddle_storage_subs; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.paddle_storage_subs ENABLE ROW LEVEL SECURITY;

--
-- Name: pro_pubkeys; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.pro_pubkeys ENABLE ROW LEVEL SECURITY;

--
-- Name: pro_pubkeys pro_pubkeys_owner_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY pro_pubkeys_owner_select ON public.pro_pubkeys FOR SELECT USING ((pubkey = ((auth.jwt() -> 'app_metadata'::text) ->> 'pubkey'::text)));


--
-- Name: pubkey_quotas; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.pubkey_quotas ENABLE ROW LEVEL SECURITY;

--
-- Name: pubkey_quotas pubkey_quotas_owner_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY pubkey_quotas_owner_select ON public.pubkey_quotas FOR SELECT USING ((user_pubkey = ((auth.jwt() -> 'app_metadata'::text) ->> 'pubkey'::text)));


--
-- Name: timeline_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.timeline_events ENABLE ROW LEVEL SECURITY;

--
-- Name: user_settings; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.user_settings ENABLE ROW LEVEL SECURITY;

--
-- Name: user_settings user_settings_owner_delete; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY user_settings_owner_delete ON public.user_settings FOR DELETE USING ((user_pubkey = ((auth.jwt() -> 'app_metadata'::text) ->> 'pubkey'::text)));


--
-- Name: user_settings user_settings_owner_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY user_settings_owner_insert ON public.user_settings FOR INSERT WITH CHECK ((user_pubkey = ((auth.jwt() -> 'app_metadata'::text) ->> 'pubkey'::text)));


--
-- Name: user_settings user_settings_owner_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY user_settings_owner_select ON public.user_settings FOR SELECT USING ((user_pubkey = ((auth.jwt() -> 'app_metadata'::text) ->> 'pubkey'::text)));


--
-- Name: user_settings user_settings_owner_update; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY user_settings_owner_update ON public.user_settings FOR UPDATE USING ((user_pubkey = ((auth.jwt() -> 'app_metadata'::text) ->> 'pubkey'::text))) WITH CHECK ((user_pubkey = ((auth.jwt() -> 'app_metadata'::text) ->> 'pubkey'::text)));


--
-- PostgreSQL database dump complete
--


