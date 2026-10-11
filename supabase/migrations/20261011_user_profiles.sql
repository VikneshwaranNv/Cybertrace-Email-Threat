-- ============================================================================
-- CyberTrace SOC Platform: Supabase PostgreSQL Authentication & Profiles Schema
-- Migration: 20261011_user_profiles.sql
-- ============================================================================

-- 1. Create User Profiles Table linked to Supabase auth.users
create table if not exists public.profiles (
  id uuid references auth.users(id) on delete cascade primary key,
  email text unique not null,
  full_name text not null,
  role text default 'ANALYST' check (role in ('ANALYST', 'SENIOR_ANALYST', 'ADMIN', 'AUDITOR')),
  badge_number text,
  organization text default 'CyberTrace SOC Operations',
  email_verified boolean default false,
  created_at timestamptz default timezone('utc'::text, now()) not null,
  updated_at timestamptz default timezone('utc'::text, now()) not null
);

-- 2. Indexes for High-Performance Queries
create index if not exists idx_profiles_email on public.profiles(email);
create index if not exists idx_profiles_role on public.profiles(role);

-- 3. Enable Row Level Security (RLS)
alter table public.profiles enable row level security;

-- 4. Restrictive RLS Policies
-- Allow authenticated users to view only their own profile
create policy "Users can view their own profile"
  on public.profiles
  for select
  to authenticated
  using (auth.uid() = id);

-- Allow authenticated users to update only their own profile
create policy "Users can update their own profile"
  on public.profiles
  for update
  to authenticated
  using (auth.uid() = id)
  with check (auth.uid() = id);

-- Allow admins to view all profiles for operator management
create policy "Admins can view all profiles"
  on public.profiles
  for select
  to authenticated
  using (
    exists (
      select 1 from public.profiles
      where id = auth.uid() and role = 'ADMIN'
    )
  );

-- Service role has administrative oversight (automated sync)
create policy "Service role has full access"
  on public.profiles
  for all
  to service_role
  using (true)
  with check (true);

-- 5. Automatic Profile Provisioning Trigger on User Sign-Up
create or replace function public.handle_new_user()
returns trigger as $$
declare
  raw_name text;
  badge_val text;
begin
  raw_name := coalesce(new.raw_user_meta_data->>'full_name', split_part(new.email, '@', 1));
  badge_val := 'SOC-' || substring(new.id::text from 1 for 4);

  insert into public.profiles (id, email, full_name, role, badge_number, organization, email_verified)
  values (
    new.id,
    new.email,
    raw_name,
    coalesce(new.raw_user_meta_data->>'role', 'ANALYST'),
    badge_val,
    'CyberTrace SOC Operations',
    coalesce(new.email_confirmed_at is not null, false)
  )
  on conflict (id) do update set
    email = excluded.email,
    full_name = coalesce(excluded.full_name, profiles.full_name),
    updated_at = now();

  return new;
end;
$$ language plpgsql security definer;

-- Trigger execution on auth.users insert
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- 6. Trigger to Update `updated_at` Timestamp
create or replace function public.update_updated_at_column()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

drop trigger if exists set_profiles_timestamp on public.profiles;
create trigger set_profiles_timestamp
  before update on public.profiles
  for each row execute procedure public.update_updated_at_column();
