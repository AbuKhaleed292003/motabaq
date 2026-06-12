-- ============================================================
-- مُطابق — هجرة قاعدة البيانات (Supabase / Postgres)
-- الأساس: جداول متعدّدة المنشآت + عزل صارم بـRLS + تهيئة تلقائية
-- طريقة التطبيق: Supabase ← SQL Editor ← الصق هذا الملف ← Run
-- ============================================================

create extension if not exists pgcrypto;

-- ============================================================
-- 1) الجداول
-- ============================================================

-- ملف المستخدم (1:1 مع auth.users)
create table if not exists profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  full_name   text,
  phone       text,
  locale      text default 'ar',
  created_at  timestamptz default now()
);

-- الحساب الدافع: منشأة مفردة (sme) أو مكتب محاسبة (office)
create table if not exists accounts (
  id          uuid primary key default gen_random_uuid(),
  name        text not null,
  type        text not null default 'sme',          -- sme | office
  owner_id    uuid references auth.users(id),
  created_at  timestamptz default now()
);

-- ربط المستخدمين بالحسابات بدور
create table if not exists memberships (
  id          uuid primary key default gen_random_uuid(),
  account_id  uuid references accounts(id) on delete cascade,
  user_id     uuid references auth.users(id) on delete cascade,
  role        text not null default 'member',       -- owner | admin | member | viewer
  created_at  timestamptz default now(),
  unique (account_id, user_id)
);

-- المنشأة المُراقَبة
create table if not exists establishments (
  id          uuid primary key default gen_random_uuid(),
  account_id  uuid references accounts(id) on delete cascade,
  name        text not null,
  cr_number   text,                                  -- السجل التجاري
  activity    text,
  size        text,
  city        text,
  created_at  timestamptz default now()
);

-- حالة كل جهة لكل منشأة
create table if not exists compliance_items (
  id               uuid primary key default gen_random_uuid(),
  establishment_id uuid references establishments(id) on delete cascade,
  authority        text not null,                    -- nitaqat|zakat|einvoice|cr|gosi|municipal
  status           text not null default 'pending',  -- ok|warn|risk|pending
  score            int  default 0,                   -- 0..100
  data             jsonb,
  note             text,
  updated_at       timestamptz default now(),
  unique (establishment_id, authority)
);

-- المواعيد الحرجة
create table if not exists deadlines (
  id               uuid primary key default gen_random_uuid(),
  establishment_id uuid references establishments(id) on delete cascade,
  title            text not null,
  authority        text,
  due_date         date,
  level            text default 'ok',                -- ok|warn|risk
  created_at       timestamptz default now()
);

-- سجلّ التقارير المُرسَلة
create table if not exists reports (
  id               uuid primary key default gen_random_uuid(),
  establishment_id uuid references establishments(id) on delete cascade,
  generated_by     uuid references auth.users(id),
  sent_to_email    text,
  score            int,
  payload          jsonb,
  created_at       timestamptz default now()
);

-- التنبيهات
create table if not exists alerts (
  id               uuid primary key default gen_random_uuid(),
  establishment_id uuid references establishments(id) on delete cascade,
  type             text,
  message          text,
  channel          text,                             -- email|whatsapp
  status           text default 'queued',
  sent_at          timestamptz
);

-- الخطط
create table if not exists plans (
  id        text primary key,                        -- free|basic|pro|office
  name      text,
  price_sar numeric,
  features  jsonb
);

-- الاشتراكات (تُدار من الخادم/Moyasar لاحقاً)
create table if not exists subscriptions (
  id            uuid primary key default gen_random_uuid(),
  account_id    uuid references accounts(id) on delete cascade,
  plan_id       text references plans(id),
  status        text default 'trial',                -- trial|active|past_due|canceled
  provider      text default 'moyasar',
  provider_ref  text,
  period_end    timestamptz,
  created_at    timestamptz default now()
);

-- سجلّ التدقيق
create table if not exists audit_log (
  id          uuid primary key default gen_random_uuid(),
  account_id  uuid references accounts(id) on delete cascade,
  user_id     uuid references auth.users(id),
  action      text,
  entity      text,
  meta        jsonb,
  created_at  timestamptz default now()
);

-- فهارس على المفاتيح الأجنبية
create index if not exists idx_memberships_user      on memberships(user_id);
create index if not exists idx_establishments_account on establishments(account_id);
create index if not exists idx_compliance_est         on compliance_items(establishment_id);
create index if not exists idx_deadlines_est          on deadlines(establishment_id);
create index if not exists idx_reports_est            on reports(establishment_id);
create index if not exists idx_alerts_est             on alerts(establishment_id);
create index if not exists idx_subscriptions_account  on subscriptions(account_id);

-- ============================================================
-- 2) دوال مساعدة (SECURITY DEFINER لتفادي تكرار RLS)
-- ============================================================

create or replace function my_account_ids()
returns setof uuid language sql security definer stable
set search_path = public as $$
  select account_id from memberships where user_id = auth.uid()
$$;

create or replace function my_establishment_ids()
returns setof uuid language sql security definer stable
set search_path = public as $$
  select id from establishments
  where account_id in (select account_id from memberships where user_id = auth.uid())
$$;

-- ============================================================
-- 3) تهيئة الحساب تلقائياً عند تسجيل مستخدم جديد
-- ============================================================

create or replace function handle_new_user()
returns trigger language plpgsql security definer
set search_path = public as $$
declare new_account uuid;
begin
  insert into profiles (id, full_name)
    values (new.id, coalesce(new.raw_user_meta_data->>'full_name', ''));

  insert into accounts (name, type, owner_id)
    values (coalesce(new.raw_user_meta_data->>'full_name', 'منشأتي'), 'sme', new.id)
    returning id into new_account;

  insert into memberships (account_id, user_id, role)
    values (new_account, new.id, 'owner');

  insert into subscriptions (account_id, plan_id, status)
    values (new_account, 'free', 'trial');

  return new;
end; $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function handle_new_user();

-- ============================================================
-- 4) تفعيل RLS على كل الجداول
-- ============================================================

alter table profiles         enable row level security;
alter table accounts         enable row level security;
alter table memberships      enable row level security;
alter table establishments   enable row level security;
alter table compliance_items enable row level security;
alter table deadlines        enable row level security;
alter table reports          enable row level security;
alter table alerts           enable row level security;
alter table plans            enable row level security;
alter table subscriptions    enable row level security;
alter table audit_log        enable row level security;

-- profiles: المستخدم يرى/يعدّل ملفه فقط
create policy profiles_self on profiles
  for all to authenticated
  using (id = auth.uid()) with check (id = auth.uid());

-- accounts: يرى حساباته؛ ينشئ حساباً يملكه؛ المالك فقط يعدّل/يحذف
create policy accounts_select on accounts
  for select to authenticated
  using (id in (select my_account_ids()));
create policy accounts_insert on accounts
  for insert to authenticated
  with check (owner_id = auth.uid());
create policy accounts_modify on accounts
  for update to authenticated
  using (owner_id = auth.uid()) with check (owner_id = auth.uid());
create policy accounts_delete on accounts
  for delete to authenticated
  using (owner_id = auth.uid());

-- memberships: يرى عضوياته وأعضاء حساباته؛ مالك الحساب يدير العضويات
create policy memberships_select on memberships
  for select to authenticated
  using (user_id = auth.uid() or account_id in (select my_account_ids()));
create policy memberships_write on memberships
  for all to authenticated
  using (account_id in (select id from accounts where owner_id = auth.uid()))
  with check (account_id in (select id from accounts where owner_id = auth.uid()));

-- establishments: ضمن حسابات المستخدم فقط
create policy est_all on establishments
  for all to authenticated
  using (account_id in (select my_account_ids()))
  with check (account_id in (select my_account_ids()));

-- الجداول التابعة: عبر establishment ضمن حسابات المستخدم
create policy compliance_all on compliance_items
  for all to authenticated
  using (establishment_id in (select my_establishment_ids()))
  with check (establishment_id in (select my_establishment_ids()));

create policy deadlines_all on deadlines
  for all to authenticated
  using (establishment_id in (select my_establishment_ids()))
  with check (establishment_id in (select my_establishment_ids()));

create policy reports_all on reports
  for all to authenticated
  using (establishment_id in (select my_establishment_ids()))
  with check (establishment_id in (select my_establishment_ids()));

create policy alerts_all on alerts
  for all to authenticated
  using (establishment_id in (select my_establishment_ids()))
  with check (establishment_id in (select my_establishment_ids()));

-- subscriptions: قراءة فقط للمستخدم؛ الكتابة من الخادم (service role يتجاوز RLS)
create policy subs_select on subscriptions
  for select to authenticated
  using (account_id in (select my_account_ids()));

-- plans: كتالوج عام للقراءة
create policy plans_read on plans
  for select to authenticated using (true);

-- audit_log: ضمن حسابات المستخدم
create policy audit_select on audit_log
  for select to authenticated
  using (account_id in (select my_account_ids()));
create policy audit_insert on audit_log
  for insert to authenticated
  with check (account_id in (select my_account_ids()));

-- ============================================================
-- 5) تهيئة الخطط الأولية
-- ============================================================

insert into plans (id, name, price_sar, features) values
  ('free',  'مجاني',   0,    '{"establishments": 1}'),
  ('basic', 'أساسي',   149,  '{"establishments": 5}'),
  ('pro',   'احترافي', 399,  '{"establishments": 25}'),
  ('office','المكاتب', null, '{"establishments": "unlimited"}')
on conflict (id) do nothing;

-- ============================================================
-- تمّ. الخطوة التالية: شاشات الدخول/التسجيل ثم نقل اللوحة لقراءة هذه البيانات.
-- ============================================================
