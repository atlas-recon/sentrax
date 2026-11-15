create type public.app_role as enum ('admin', 'user');
create table public.user_roles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade not null,
  role app_role not null,
  unique (user_id, role)
);
grant select on public.user_roles to authenticated;
grant all on public.user_roles to service_role;
alter table public.user_roles enable row level security;

create or replace function public.has_role(_user_id uuid, _role app_role)
returns boolean language sql stable security definer set search_path = public
as $$ select exists (select 1 from public.user_roles where user_id = _user_id and role = _role) $$;

create policy "own roles read" on public.user_roles for select to authenticated
  using (auth.uid() = user_id or public.has_role(auth.uid(), 'admin'));

-- Block plan self-upgrades
create or replace function public.protect_profile_plan()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.plan is distinct from old.plan
     and coalesce(current_setting('app.plan_change', true), '') <> 'on'
     and not public.has_role(auth.uid(), 'admin') then
    new.plan := old.plan;
  end if;
  return new;
end; $$;
create trigger trg_protect_profile_plan before update on public.profiles
  for each row execute function public.protect_profile_plan();

create policy "admin read profiles" on public.profiles for select to authenticated
  using (public.has_role(auth.uid(), 'admin'));
create policy "admin read payments" on public.payment_requests for select to authenticated
  using (public.has_role(auth.uid(), 'admin'));

create or replace function public.admin_review_payment(_request_id uuid, _approve boolean)
returns void language plpgsql security definer set search_path = public as $$
declare r public.payment_requests;
begin
  if not public.has_role(auth.uid(), 'admin') then raise exception 'Not authorized'; end if;
  select * into r from public.payment_requests where id = _request_id;
  if not found then raise exception 'Request not found'; end if;
  update public.payment_requests set status = case when _approve then 'confirmed' else 'rejected' end where id = _request_id;
  if _approve then
    perform set_config('app.plan_change', 'on', true);
    update public.profiles set plan = r.plan where id = r.user_id;
  end if;
end; $$;

create or replace function public.admin_set_plan(_user_id uuid, _plan text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.has_role(auth.uid(), 'admin') then raise exception 'Not authorized'; end if;
  if _plan not in ('free','pro','business') then raise exception 'Invalid plan'; end if;
  perform set_config('app.plan_change', 'on', true);
  update public.profiles set plan = _plan where id = _user_id;
end; $$;

revoke execute on function public.admin_review_payment(uuid, boolean) from public, anon;
revoke execute on function public.admin_set_plan(uuid, text) from public, anon;
grant execute on function public.admin_review_payment(uuid, boolean) to authenticated;
grant execute on function public.admin_set_plan(uuid, text) to authenticated;

insert into public.user_roles (user_id, role)
select id, 'admin' from auth.users where email = 'arqamsaleh66@gmail.com'
on conflict do nothing;