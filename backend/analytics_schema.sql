-- ===========================================
-- ANALYTICS SYSTEM SCHEMA
-- Database tables for seller-focused marketplace analytics
-- ===========================================

-- Enable required extensions
create extension if not exists pgcrypto;
create extension if not exists "uuid-ossp";

-- ===========================================
-- LISTING VIEWS TRACKING
-- ===========================================

create table if not exists public.listing_views (
    id uuid primary key default gen_random_uuid(),
    listing_id uuid not null references public.listings(id) on delete cascade,
    viewer_id uuid references public.profiles(id), -- NULL for anonymous
    session_id varchar(255), -- Track anonymous sessions
    ip_address inet,
    user_agent text,
    referrer_url text,
    country_code varchar(2),
    source varchar(50), -- 'direct', 'search', 'social', 'referral'
    campaign_id varchar(100),
    search_query text,
    viewed_at timestamp with time zone default now(),

    -- Constraints
    constraint listing_views_session_id_not_empty check (session_id != ''),
    constraint listing_views_source_valid check (source in ('direct', 'search', 'social', 'referral'))
);

-- Performance indexes for listing_views
create index if not exists idx_listing_views_listing_id on public.listing_views(listing_id);
create index if not exists idx_listing_views_viewed_at on public.listing_views(viewed_at);
create index if not exists idx_listing_views_session_id on public.listing_views(session_id);
create index if not exists idx_listing_views_country on public.listing_views(country_code);
create index if not exists idx_listing_views_source on public.listing_views(source);
create index if not exists idx_listing_views_viewer_id on public.listing_views(viewer_id);

-- ===========================================
-- ANALYTICS CACHE SYSTEM
-- ===========================================

create table if not exists public.listing_analytics_cache (
    id uuid primary key default gen_random_uuid(),
    listing_id uuid not null references public.listings(id) on delete cascade,
    cache_key varchar(255) not null,
    data jsonb not null,
    created_at timestamp with time zone default now(),
    expires_at timestamp with time zone,

    -- Constraints
    constraint listing_analytics_cache_key_not_empty check (cache_key != ''),
    unique(listing_id, cache_key)
);

-- Performance indexes for analytics cache
create index if not exists idx_cache_listing_id on public.listing_analytics_cache(listing_id);
create index if not exists idx_cache_expires_at on public.listing_analytics_cache(expires_at);

-- ===========================================
-- ANALYTICS EVENTS TRACKING
-- ===========================================

create table if not exists public.analytics_events (
    id uuid primary key default gen_random_uuid(),
    event_type varchar(50) not null, -- 'view', 'click', 'add_to_cart', 'purchase'
    listing_id uuid references public.listings(id),
    user_id uuid references public.profiles(id),
    session_id varchar(255),
    event_data jsonb default '{}'::jsonb, -- Store additional context
    created_at timestamp with time zone default now(),

    -- Constraints
    constraint analytics_events_type_not_empty check (event_type != ''),
    constraint analytics_events_valid_type check (event_type in ('view', 'click', 'add_to_cart', 'purchase', 'share', 'contact_seller'))
);

-- Performance indexes for analytics events
create index if not exists idx_event_type on public.analytics_events(event_type);
create index if not exists idx_event_created_at on public.analytics_events(created_at);
create index if not exists idx_event_listing on public.analytics_events(listing_id);
create index if not exists idx_event_user on public.analytics_events(user_id);

-- ===========================================
-- CONVERSION FUNNEL TRACKING
-- ===========================================

create table if not exists public.conversion_funnel_steps (
    id uuid primary key default gen_random_uuid(),
    listing_id uuid not null references public.listings(id) on delete cascade,
    user_id uuid references public.profiles(id),
    session_id varchar(255) not null,
    step varchar(50) not null, -- 'view', 'add_to_cart', 'checkout', 'purchase'
    step_data jsonb default '{}'::jsonb,
    created_at timestamp with time zone default now(),

    -- Constraints
    constraint conversion_funnel_step_valid check (step in ('view', 'add_to_cart', 'checkout', 'purchase')),
    constraint conversion_funnel_session_not_empty check (session_id != '')
);

-- Performance indexes for conversion funnel
create index if not exists idx_funnel_listing_id on public.conversion_funnel_steps(listing_id);
create index if not exists idx_funnel_user_id on public.conversion_funnel_steps(user_id);
create index if not exists idx_funnel_session_id on public.conversion_funnel_steps(session_id);
create index if not exists idx_funnel_created_at on public.conversion_funnel_steps(created_at);

-- ===========================================
-- ANALYTICS DASHBOARD CACHE
-- ===========================================

create table if not exists public.seller_analytics_cache (
    id uuid primary key default gen_random_uuid(),
    seller_id uuid not null references public.profiles(id) on delete cascade,
    cache_key varchar(255) not null,
    data jsonb not null,
    created_at timestamp with time zone default now(),
    expires_at timestamp with time zone,

    -- Constraints
    constraint seller_analytics_cache_key_not_empty check (cache_key != ''),
    unique(seller_id, cache_key)
);

-- Performance indexes for seller analytics cache
create index if not exists idx_seller_cache_seller_id on public.seller_analytics_cache(seller_id);
create index if not exists idx_seller_cache_expires_at on public.seller_analytics_cache(expires_at);

-- ===========================================
-- ROW LEVEL SECURITY POLICIES
-- ===========================================

-- Enable RLS on all analytics tables
alter table public.listing_views enable row level security;
alter table public.listing_analytics_cache enable row level security;
alter table public.analytics_events enable row level security;
alter table public.conversion_funnel_steps enable row level security;
alter table public.seller_analytics_cache enable row level security;

-- RLS Policies for listing_views
-- Sellers can view views of their own listings
drop policy if exists listing_views_seller_select on public.listing_views;
create policy listing_views_seller_select on public.listing_views
    for select using (
        exists (
            select 1 from public.listings l
            where l.id = listing_id and l.seller_id = auth.uid()
        )
    );

-- Allow inserts for tracking (will be controlled by application logic)
drop policy if exists listing_views_insert on public.listing_views;
create policy listing_views_insert on public.listing_views
    for insert with check (true);

-- RLS Policies for listing_analytics_cache
-- Sellers can view cache for their own listings
drop policy if exists listing_cache_seller_select on public.listing_analytics_cache;
create policy listing_cache_seller_select on public.listing_analytics_cache
    for select using (
        exists (
            select 1 from public.listings l
            where l.id = listing_id and l.seller_id = auth.uid()
        )
    );

-- Allow inserts/updates for cache management
drop policy if exists listing_cache_insert on public.listing_analytics_cache;
create policy listing_cache_insert on public.listing_analytics_cache
    for insert with check (true);

drop policy if exists listing_cache_update on public.listing_analytics_cache;
create policy listing_cache_update on public.listing_analytics_cache
    for update using (true);

drop policy if exists listing_cache_delete on public.listing_analytics_cache;
create policy listing_cache_delete on public.listing_analytics_cache
    for delete using (true);

-- RLS Policies for analytics_events
-- Sellers can view events for their own listings
drop policy if exists analytics_events_seller_select on public.analytics_events;
create policy analytics_events_seller_select on public.analytics_events
    for select using (
        listing_id is null or exists (
            select 1 from public.listings l
            where l.id = listing_id and l.seller_id = auth.uid()
        )
    );

-- Allow inserts for event tracking
drop policy if exists analytics_events_insert on public.analytics_events;
create policy analytics_events_insert on public.analytics_events
    for insert with check (true);

-- RLS Policies for conversion_funnel_steps
-- Sellers can view funnel steps for their own listings
drop policy if exists funnel_seller_select on public.conversion_funnel_steps;
create policy funnel_seller_select on public.conversion_funnel_steps
    for select using (
        exists (
            select 1 from public.listings l
            where l.id = listing_id and l.seller_id = auth.uid()
        )
    );

-- Allow inserts for funnel tracking
drop policy if exists funnel_insert on public.conversion_funnel_steps;
create policy funnel_insert on public.conversion_funnel_steps
    for insert with check (true);

-- RLS Policies for seller_analytics_cache
-- Sellers can only view their own cache
drop policy if exists seller_cache_owner on public.seller_analytics_cache;
create policy seller_cache_owner on public.seller_analytics_cache
    for all using (seller_id = auth.uid());

-- ===========================================
-- UTILITY FUNCTIONS
-- ===========================================

-- Function to get country from IP (requires external service)
create or replace function get_country_from_ip(ip_address inet)
returns varchar(2)
language plpgsql
as $$
begin
    -- This would integrate with an IP geolocation service
    -- For now, return NULL
    return null;
end;
$$;

-- Function to clean expired cache entries
create or replace function cleanup_expired_cache()
returns integer
language plpgsql
as $$
declare
    deleted_count integer;
begin
    -- Clean listing analytics cache
    delete from public.listing_analytics_cache
    where expires_at < now();

    -- Clean seller analytics cache
    delete from public.seller_analytics_cache
    where expires_at < now();

    get diagnostics deleted_count = row_count;
    return deleted_count;
end;
$$;

-- Function to invalidate cache for a listing
create or replace function invalidate_listing_cache(listing_uuid uuid)
returns void
language plpgsql
as $$
begin
    delete from public.listing_analytics_cache
    where listing_id = listing_uuid;
end;
$$;

-- Function to aggregate daily analytics (for background processing)
create or replace function aggregate_daily_analytics(target_date date default current_date - interval '1 day')
returns void
language plpgsql
as $$
begin
    -- This function would be called by a scheduled job
    -- Implementation depends on specific aggregation needs
    null;
end;
$$;

-- ===========================================
-- PERFORMANCE OPTIMIZATION
-- ===========================================

-- Create composite indexes for common queries
create index if not exists idx_listing_views_listing_date on public.listing_views(listing_id, viewed_at);
create index if not exists idx_listing_views_session_date on public.listing_views(session_id, viewed_at);
create index if not exists idx_events_listing_date on public.analytics_events(listing_id, created_at);
create index if not exists idx_funnel_listing_date on public.conversion_funnel_steps(listing_id, created_at);

-- Additional index for listing views (removed partial index due to subquery limitation)
create index if not exists idx_listing_views_listing_viewer on public.listing_views(listing_id, viewer_id, viewed_at);

-- ===========================================
-- DATA RETENTION POLICIES
-- ===========================================

-- Create policy to automatically delete old view data (GDPR compliance)
-- Note: Adjust retention period based on business requirements
create or replace function cleanup_old_analytics_data()
returns void
language plpgsql
as $$
begin
    -- Delete views older than 2 years
    delete from public.listing_views
    where viewed_at < now() - interval '2 years';

    -- Delete events older than 2 years
    delete from public.analytics_events
    where created_at < now() - interval '2 years';

    -- Delete funnel steps older than 1 year
    delete from public.conversion_funnel_steps
    where created_at < now() - interval '1 year';
end;
$$;

-- ===========================================
-- COMMENTS FOR DOCUMENTATION
-- ===========================================

comment on table public.listing_views is 'Tracks all views of marketplace listings for analytics';
comment on table public.listing_analytics_cache is 'Caches computed analytics data to improve performance';
comment on table public.analytics_events is 'Tracks user interactions and conversion events';
comment on table public.conversion_funnel_steps is 'Tracks user journey through purchase funnel';
comment on table public.seller_analytics_cache is 'Caches seller dashboard analytics data';

-- ===========================================
-- INITIAL DATA SEEDING (Optional)
-- ===========================================

-- Insert some sample data for testing (uncomment if needed)
-- Note: This is for development/testing only

/*
-- Sample view data
insert into public.listing_views (listing_id, session_id, country_code, source, viewed_at)
select
    l.id,
    'session_' || generate_series(1, 100),
    case (random() * 10)::int % 5
        when 0 then 'US'
        when 1 then 'UK'
        when 2 then 'DE'
        when 3 then 'FR'
        when 4 then 'CA'
    end,
    case (random() * 10)::int % 4
        when 0 then 'direct'
        when 1 then 'search'
        when 2 then 'social'
        when 3 then 'referral'
    end,
    now() - (random() * 30 || ' days')::interval
from public.listings l
limit 10;
*/
