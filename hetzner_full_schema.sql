-- ============================================================================
-- SmartCaptcha — 100% Standalone Hetzner PostgreSQL Schema (Zero Supabase Needed)
-- Supports: Auth, Profiles, Device Lock, High-Speed Redis Captcha Batching,
--           8-Level Team Tree, Deposits, Withdrawals, Support Tickets &
--           365-Day Compounding Plan (10 Lakh+ Users Ready)
-- ============================================================================

create extension if not exists pgcrypto;

-- 1. Standalone Users Auth Table (replaces Supabase auth.users)
create table if not exists public.users (
  id uuid primary key default gen_random_uuid(),
  email text unique not null,
  password_hash text not null,
  role text not null default 'user' check (role in ('user', 'admin')),
  is_anonymous boolean not null default false,
  created_at timestamptz not null default now()
);

-- 2. User Profiles & O(1) Cached Wallet Balance
create table if not exists public.profiles (
  id uuid primary key references public.users(id) on delete cascade,
  email text,
  full_name text,
  phone text,
  gender text,
  date_of_birth text,
  city text,
  state text,
  pin_code text,
  referral_code text unique,
  referred_by uuid references public.users(id) on delete set null,
  account_status text not null default 'active' check (account_status in ('active', 'pending', 'review', 'blocked')),
  device_token text,
  device_locked boolean not null default true,
  is_admin boolean not null default false,
  balance_usdt numeric(14, 4) not null default 0,
  total_captchas_solved bigint not null default 0,
  today_captchas_count integer not null default 0,
  today_captchas_date date not null default ((now() at time zone 'Asia/Kolkata')::date),
  created_at timestamptz not null default now()
);

create index if not exists idx_profiles_phone on public.profiles(phone);
create index if not exists idx_profiles_ref_code on public.profiles(referral_code);
create index if not exists idx_profiles_referred_by on public.profiles(referred_by);
create index if not exists idx_profiles_device_token on public.profiles(device_token);
create index if not exists idx_profiles_balance on public.profiles(balance_usdt desc);

-- 3. Wallet Ledger
create table if not exists public.wallet_ledger (
  id bigserial primary key,
  user_id uuid not null references public.users(id) on delete cascade,
  entry_type text not null,
  amount numeric(14, 4) not null,
  description text,
  created_at timestamptz not null default now()
);

create index if not exists idx_wallet_ledger_user_created on public.wallet_ledger(user_id, created_at desc);

-- Auto-sync cached profiles.balance_usdt on every ledger insert/delete
create or replace function public.fn_sync_profile_balance_from_ledger()
returns trigger
language plpgsql
as $$
begin
  if tg_op = 'INSERT' then
    update public.profiles
    set balance_usdt = round((coalesce(balance_usdt, 0) + new.amount)::numeric, 4)
    where id = new.user_id;
    return new;
  elsif tg_op = 'DELETE' then
    update public.profiles
    set balance_usdt = round((coalesce(balance_usdt, 0) - old.amount)::numeric, 4)
    where id = old.user_id;
    return old;
  end if;
  return null;
end;
$$;

drop trigger if exists trg_wallet_ledger_sync_balance on public.wallet_ledger;
create trigger trg_wallet_ledger_sync_balance
  after insert or delete on public.wallet_ledger
  for each row
  execute function public.fn_sync_profile_balance_from_ledger();

-- 4. Deposits & Withdrawals
create table if not exists public.deposits (
  id bigserial primary key,
  user_id uuid not null references public.users(id) on delete cascade,
  amount_usdt numeric(14, 4) not null check (amount_usdt > 0),
  tx_id text not null,
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  admin_note text,
  created_at timestamptz not null default now(),
  settled_at timestamptz
);
create index if not exists idx_deposits_user_status_created on public.deposits(user_id, status, created_at desc);

create table if not exists public.withdrawal_requests (
  id bigserial primary key,
  user_id uuid not null references public.users(id) on delete cascade,
  amount numeric(14, 4) not null check (amount > 0),
  payout_method text not null default 'USDT BEP-20',
  payout_details_masked text,
  payout_address text,
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  required_deposit_usdt numeric(14, 4) not null default 0,
  admin_note text,
  created_at timestamptz not null default now(),
  settled_at timestamptz
);
create index if not exists idx_withdrawals_user_status_created on public.withdrawal_requests(user_id, status, created_at desc);

-- 5. Platform Settings Tables
create table if not exists public.app_settings (
  id integer primary key default 1 check (id = 1),
  registration_open boolean not null default true,
  max_registered integer not null default 1000000,
  device_lock_enabled boolean not null default true,
  level_count integer not null default 8,
  level_income jsonb not null default '[10,5,3,2,2,1,1,1]'::jsonb,
  captcha_mode text not null default 'standard',
  updated_at timestamptz not null default now()
);
insert into public.app_settings (id) values (1) on conflict (id) do nothing;

create table if not exists public.platform_settings (
  id integer primary key default 1 check (id = 1),
  withdraw_rule_json jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);
insert into public.platform_settings (id) values (1) on conflict (id) do nothing;

create table if not exists public.public_withdraw_config (
  id integer primary key default 1 check (id = 1),
  amounts jsonb not null default '[5,10,25,50,100]'::jsonb,
  amount_conditions jsonb not null default '[]'::jsonb,
  chart jsonb not null default '[]'::jsonb,
  deposit_address text default '',
  deposit_qr text default '',
  updated_at timestamptz not null default now()
);
insert into public.public_withdraw_config (id) values (1) on conflict (id) do nothing;

create table if not exists public.income_settings (
  id integer primary key default 1 check (id = 1),
  captcha_daily_limit integer not null default 50,
  captcha_reward_usdt numeric(10, 4) not null default 0.01,
  signup_bonus_usdt numeric(10, 4) not null default 0,
  fast_start_bonus_usdt numeric(10, 4) not null default 0,
  streak_bonus_usdt numeric(10, 4) not null default 0,
  updated_at timestamptz not null default now()
);
insert into public.income_settings (id) values (1) on conflict (id) do nothing;

create table if not exists public.income_runs (
  id bigserial primary key,
  run_date date unique not null,
  users_credited integer not null default 0,
  total_usdt numeric(14, 4) not null default 0,
  created_at timestamptz not null default now()
);

-- 6. Support Tickets
create table if not exists public.support_tickets (
  id bigserial primary key,
  user_id uuid not null references public.users(id) on delete cascade,
  subject text not null,
  status text not null default 'open' check (status in ('open', 'answered', 'closed')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists idx_tickets_user on public.support_tickets(user_id, updated_at desc);

create table if not exists public.ticket_messages (
  id bigserial primary key,
  ticket_id bigint not null references public.support_tickets(id) on delete cascade,
  sender text not null check (sender in ('user', 'admin')),
  body text not null,
  created_at timestamptz not null default now()
);
create index if not exists idx_ticket_messages_ticket on public.ticket_messages(ticket_id, created_at asc);

-- 7. 365-Day Compounding Tables
create table if not exists public.compounding_settings (
  id integer primary key default 1 check (id = 1),
  enabled boolean not null default true,
  duration_days integer not null default 365 check (duration_days between 1 and 3650),
  daily_rate_pct numeric(10, 6) not null default 0.746585 check (daily_rate_pct >= 0 and daily_rate_pct <= 50),
  monthly_target_pct numeric(6, 2) not null default 25.00,
  allowed_amounts_inr jsonb not null default '[1000, 2000, 4000, 10000]'::jsonb,
  allow_custom_amount boolean not null default false,
  min_custom_inr numeric(12, 2) not null default 1000,
  max_custom_inr numeric(12, 2) not null default 100000,
  max_active_plans_per_user integer not null default 5 check (max_active_plans_per_user between 1 and 100),
  credit_mode text not null default 'compound_to_plan_wallet'
    check (credit_mode in ('compound_to_plan_wallet', 'daily_to_main_wallet')),
  early_exit_enabled boolean not null default false,
  early_exit_penalty_pct numeric(5, 2) not null default 10.00,
  require_active_account boolean not null default true,
  daily_company_cap_inr numeric(14, 2) not null default 500000,
  updated_at timestamptz not null default now()
);
insert into public.compounding_settings (id) values (1) on conflict (id) do nothing;

create table if not exists public.compounding_plans (
  id bigserial primary key,
  user_id uuid not null references public.users(id) on delete cascade,
  principal_inr numeric(14, 2) not null check (principal_inr > 0),
  principal_usdt numeric(14, 4) not null check (principal_usdt > 0),
  current_balance_inr numeric(14, 2) not null check (current_balance_inr >= 0),
  total_profit_inr numeric(14, 2) not null default 0,
  daily_rate_pct numeric(10, 6) not null,
  duration_days integer not null default 365,
  days_completed integer not null default 0,
  projected_maturity_inr numeric(14, 2) not null,
  credit_mode text not null default 'compound_to_plan_wallet',
  status text not null default 'active' check (status in ('active', 'paused', 'completed', 'cancelled')),
  started_at timestamptz not null default now(),
  last_credited_date date,
  matured_at timestamptz,
  created_by_admin boolean not null default false,
  admin_note text
);
create index if not exists idx_compounding_plans_user on public.compounding_plans(user_id, status);
create index if not exists idx_compounding_plans_status_date on public.compounding_plans(status, last_credited_date);

create table if not exists public.compounding_daily_logs (
  id bigserial primary key,
  plan_id bigint not null references public.compounding_plans(id) on delete cascade,
  user_id uuid not null references public.users(id) on delete cascade,
  credit_date date not null,
  day_number integer not null,
  opening_balance_inr numeric(14, 2) not null,
  profit_inr numeric(14, 2) not null,
  closing_balance_inr numeric(14, 2) not null,
  credited_to_main_wallet boolean not null default false,
  created_at timestamptz not null default now(),
  unique (plan_id, credit_date)
);
create index if not exists idx_compounding_logs_plan on public.compounding_daily_logs(plan_id, day_number desc);

-- 8. High-Speed Batch Captcha Flush Function (Redis -> PostgreSQL)
create or replace function public.batch_credit_captchas(p_items jsonb)
returns jsonb
language plpgsql
as $$
declare
  v_today date := (now() at time zone 'Asia/Kolkata')::date;
  v_users integer := 0;
  v_captchas bigint := 0;
begin
  if p_items is null or jsonb_typeof(p_items) <> 'array' or jsonb_array_length(p_items) = 0 then
    return jsonb_build_object('ok', true, 'users', 0, 'captchas', 0);
  end if;

  with parsed as (
    select
      (item->>'user_id')::uuid as user_id,
      greatest(0, (item->>'solved')::bigint) as solved,
      round(greatest(0, (item->>'reward_usdt')::numeric), 4) as reward_usdt
    from jsonb_array_elements(p_items) as item
    where (item->>'solved')::bigint > 0
  ),
  upd_profiles as (
    update public.profiles p
    set
      total_captchas_solved = p.total_captchas_solved + x.solved,
      today_captchas_count = case
        when p.today_captchas_date = v_today then p.today_captchas_count + x.solved::integer
        else x.solved::integer
      end,
      today_captchas_date = v_today
    from parsed x
    where p.id = x.user_id
    returning p.id
  ),
  ins_ledger as (
    insert into public.wallet_ledger (user_id, entry_type, amount, description)
    select x.user_id, 'captcha_income', x.reward_usdt, format('Captcha batch credit (%s solved)', x.solved)
    from parsed x
    where x.reward_usdt > 0
    returning user_id
  )
  select count(*)::integer, coalesce(sum(solved), 0)::bigint
  into v_users, v_captchas
  from parsed;

  return jsonb_build_object('ok', true, 'users', v_users, 'captchas', v_captchas, 'day', v_today);
end;
$$;

-- 9. Chunked Daily Compounding Runner
create or replace function public.run_daily_compounding_batch(
  p_day date default ((now() at time zone 'Asia/Kolkata')::date),
  p_batch_limit integer default 5000
)
returns jsonb
language plpgsql
as $$
declare
  v_set public.compounding_settings%rowtype;
  v_plan public.compounding_plans%rowtype;
  v_spent_today numeric(14, 2) := 0;
  v_profit_inr numeric(14, 2);
  v_new_balance numeric(14, 2);
  v_next_day integer;
  v_processed integer := 0;
  v_completed integer := 0;
  v_total_profit numeric(14, 2) := 0;
  v_to_main boolean;
  v_maturity_inr numeric(14, 2);
begin
  select * into v_set from public.compounding_settings where id = 1;
  if not found or not v_set.enabled then
    return jsonb_build_object('ok', false, 'message', 'Compounding plan disabled', 'processed_plans', 0);
  end if;

  select coalesce(sum(profit_inr), 0) into v_spent_today
  from public.compounding_daily_logs where credit_date = p_day;

  for v_plan in
    select * from public.compounding_plans
    where status = 'active' and days_completed < duration_days
      and (last_credited_date is null or last_credited_date < p_day)
    order by id asc limit greatest(1, least(p_batch_limit, 20000))
    for update skip locked
  loop
    v_profit_inr := round(v_plan.current_balance_inr * (v_plan.daily_rate_pct / 100.0), 2);
    if v_profit_inr <= 0 then continue; end if;
    if (v_spent_today + v_profit_inr) > v_set.daily_company_cap_inr then exit; end if;

    v_new_balance := round(v_plan.current_balance_inr + v_profit_inr, 2);
    v_next_day := v_plan.days_completed + 1;
    v_to_main := (v_plan.credit_mode = 'daily_to_main_wallet');

    insert into public.compounding_daily_logs (
      plan_id, user_id, credit_date, day_number,
      opening_balance_inr, profit_inr, closing_balance_inr, credited_to_main_wallet
    ) values (
      v_plan.id, v_plan.user_id, p_day, v_next_day,
      v_plan.current_balance_inr, v_profit_inr, v_new_balance, v_to_main
    ) on conflict (plan_id, credit_date) do nothing;
    if not found then continue; end if;

    if v_to_main then
      insert into public.wallet_ledger (user_id, entry_type, amount, description)
      values (v_plan.user_id, 'compounding_daily', round(v_profit_inr / 100.0, 4),
        format('Compounding Plan #%s Day %s/%s daily credit (₹%s)', v_plan.id, v_next_day, v_plan.duration_days, v_profit_inr));
    end if;

    if v_next_day >= v_plan.duration_days then
      v_maturity_inr := case when v_to_main then v_plan.principal_inr else v_new_balance end;
      update public.compounding_plans
      set current_balance_inr = v_new_balance, total_profit_inr = round(total_profit_inr + v_profit_inr, 2),
          days_completed = v_next_day, last_credited_date = p_day, status = 'completed', matured_at = now()
      where id = v_plan.id;

      insert into public.wallet_ledger (user_id, entry_type, amount, description)
      values (v_plan.user_id, 'compounding_maturity', round(v_maturity_inr / 100.0, 4),
        format('Compounding Plan #%s matured (%s days) - ₹%s credited', v_plan.id, v_plan.duration_days, v_maturity_inr));
      v_completed := v_completed + 1;
    else
      update public.compounding_plans
      set current_balance_inr = v_new_balance, total_profit_inr = round(total_profit_inr + v_profit_inr, 2),
          days_completed = v_next_day, last_credited_date = p_day
      where id = v_plan.id;
    end if;

    v_spent_today := v_spent_today + v_profit_inr;
    v_total_profit := v_total_profit + v_profit_inr;
    v_processed := v_processed + 1;
  end loop;

  return jsonb_build_object('ok', true, 'day', p_day, 'processed_plans', v_processed,
    'completed_plans', v_completed, 'total_profit_inr', v_total_profit,
    'has_more', v_processed >= greatest(1, least(p_batch_limit, 20000)),
    'message', format('Credited %s plans (₹%s). %s matured.', v_processed, v_total_profit, v_completed));
end;
$$;

-- 10. Multi-level Team Tree Function (8 Levels)
create or replace function public.my_team_list(p_user_id uuid, max_level integer default 8)
returns table(level integer, name text, phone text, status text, joined text)
language sql
stable
as $$
  with recursive tree as (
    select p.id, p.full_name, p.phone, p.account_status, p.created_at, 1 as lvl
    from public.profiles p
    where p.referred_by = p_user_id
    union all
    select c.id, c.full_name, c.phone, c.account_status, c.created_at, t.lvl + 1
    from public.profiles c
    join tree t on c.referred_by = t.id
    where t.lvl < greatest(1, least(max_level, 8))
  )
  select
    lvl as level,
    coalesce(full_name, '-') as name,
    case when length(coalesce(phone, '')) >= 4 then 'XXXXXX' || right(phone, 4) else '-' end as phone,
    account_status as status,
    to_char(created_at at time zone 'Asia/Kolkata', 'DD Mon YYYY') as joined
  from tree
  order by lvl asc, created_at desc
  limit 500;
$$;
