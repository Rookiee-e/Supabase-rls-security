---
name: supabase-rls-security
description: Audits and generates secure Supabase RLS policies. Use when writing, reviewing, or debugging Row Level Security policies, Supabase auth, Edge Functions, or any database authorization logic.
---

# Supabase RLS Security Audit & Generation

Production-grade security review for Supabase Row Level Security policies. Apply these rules to ALL RLS policy generation, review, and debugging.

## CRITICAL: Default Mindset

1. **Assume policies are insecure until proven otherwise**
2. **Never trust "looks right" — simulate execution paths**
3. **Think like an attacker, not a developer**
4. **RLS is behavioral, not declarative — order and composition matter**
5. **Silent failures are the norm — test adversarially**

---

## CRITICAL: Role Hierarchy & Bypass

Understand the Supabase role hierarchy before writing any policy:

| Role | Description | RLS Behavior |
|------|-------------|--------------|
| `anon` | Unauthenticated requests | RLS applies |
| `authenticated` | Logged-in users | RLS applies |
| `service_role` | Server-side admin key | **BYPASSES ALL RLS** |

**WARNING: Any query using the `service_role` key bypasses ALL RLS policies entirely. Never expose this key to clients. Use only in trusted server environments.**

```sql
-- Check current role in policy
auth.role() = 'authenticated'  -- Only logged-in users
auth.role() = 'anon'           -- Only anonymous users
```

---

## MANDATORY: Enable & Force RLS

**Do this FIRST for every table:**

```sql
-- Enable RLS (policies now apply to non-owner roles)
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

-- Force RLS even for table owner (CRITICAL for security)
ALTER TABLE documents FORCE ROW LEVEL SECURITY;
```

Without `FORCE ROW LEVEL SECURITY`, the table owner role bypasses all policies.

---

## Pre-Flight Checklist

Before writing ANY policy, verify:

```sql
-- Is RLS actually enabled?
SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public';

-- What policies exist?
SELECT * FROM pg_policies WHERE schemaname = 'public';

-- What roles have grants?
SELECT grantee, table_name, privilege_type 
FROM information_schema.table_privileges 
WHERE table_schema = 'public';
```

---

## Policy Composition Rules

**Memorize these rules:**

1. **Multiple PERMISSIVE policies = OR** — User needs to satisfy ANY ONE
2. **RESTRICTIVE policies = AND** — User must satisfy ALL restrictive policies
3. **Final access = (ANY permissive) AND (ALL restrictive)**

```sql
-- Example: Two permissive policies
CREATE POLICY "owner_read" ON docs FOR SELECT USING (auth.uid() = user_id);  -- Permissive (default)
CREATE POLICY "public_read" ON docs FOR SELECT USING (is_public = true);     -- Permissive (default)
-- Result: User can read if (owner OR public)

-- Add restrictive policy
CREATE POLICY "not_deleted" ON docs FOR SELECT AS RESTRICTIVE USING (deleted_at IS NULL);
-- Result: User can read if ((owner OR public) AND not_deleted)
```

---

## AVOID: FOR ALL Policies

**`FOR ALL` applies to SELECT, INSERT, UPDATE, and DELETE simultaneously.**

```sql
-- DANGEROUS: FOR ALL often leads to missing WITH CHECK logic
CREATE POLICY "owner_all" ON documents FOR ALL
USING (auth.uid() = user_id);
-- Missing WITH CHECK! INSERT and UPDATE are vulnerable.
```

**RULE: Always write separate policies for each operation type.**

---

## USING vs WITH CHECK — The Critical Distinction

| Clause | Applies To | Controls |
|--------|-----------|----------|
| `USING` | SELECT, UPDATE (existing rows), DELETE | Which rows can be READ |
| `WITH CHECK` | INSERT, UPDATE (new values) | Which rows can be WRITTEN |

**IMPORTANT: `WITH CHECK` only has access to `NEW` row values. `OLD` is NOT available in RLS policies—only in triggers.**

### The Privilege Escalation Pattern

```sql
-- DANGEROUS: Missing WITH CHECK
CREATE POLICY "users_update" ON profiles FOR UPDATE
USING (auth.uid() = user_id);
-- Attacker can UPDATE their row to set user_id = victim_id, then read victim's data

-- SECURE: Always pair USING with WITH CHECK
CREATE POLICY "users_update" ON profiles FOR UPDATE
USING (auth.uid() = user_id)
WITH CHECK (auth.uid() = user_id);
```

**RULE: Every UPDATE policy MUST have WITH CHECK that mirrors or restricts USING.**

---

## Ownership & Immutability

### The Mutable Ownership Attack

```sql
-- DANGEROUS: user_id is writable
CREATE POLICY "owner_access" ON documents FOR ALL
USING (auth.uid() = user_id);

-- Attacker: UPDATE documents SET user_id = 'my-id' WHERE id = 'victim-doc';
```

### Required Immutability Pattern

**Triggers are the ONLY reliable way to enforce immutability. RLS `WITH CHECK` cannot access `OLD` values.**

```sql
-- Trigger-based immutability (REQUIRED)
CREATE OR REPLACE FUNCTION immutable_user_id()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.user_id IS DISTINCT FROM NEW.user_id THEN
    RAISE EXCEPTION 'user_id cannot be modified';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_immutable_user_id
  BEFORE UPDATE ON documents
  FOR EACH ROW EXECUTE FUNCTION immutable_user_id();
```

**RULE: Ownership columns (user_id, org_id, etc.) MUST be immutable via triggers. WITH CHECK cannot prevent ownership changes.**

---

## INSERT Validation

### The Ownership Injection Attack

```sql
-- DANGEROUS: No INSERT validation
CREATE POLICY "insert_doc" ON documents FOR INSERT
WITH CHECK (true);

-- Attacker: INSERT INTO documents (user_id, content) VALUES ('victim-id', 'malicious');
```

### Secure INSERT Pattern

```sql
-- SECURE: Force ownership to authenticated user
CREATE POLICY "insert_doc" ON documents FOR INSERT
WITH CHECK (auth.uid() = user_id);

-- Or use a trigger for guaranteed ownership
CREATE OR REPLACE FUNCTION set_owner()
RETURNS TRIGGER AS $$
BEGIN
  NEW.user_id := auth.uid();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
```

---

## Join-Based Authorization Vulnerabilities

### The Writable Membership Attack

```sql
-- DANGEROUS: Membership table is writable
CREATE POLICY "team_access" ON projects FOR SELECT
USING (
  EXISTS (
    SELECT 1 FROM team_members 
    WHERE team_members.team_id = projects.team_id 
    AND team_members.user_id = auth.uid()
  )
);

-- If team_members has INSERT policy, attacker adds themselves to any team
```

### Performance: Index RLS Columns

**Join-heavy RLS policies can severely impact performance and Realtime.**

Always index columns used in RLS subqueries:

```sql
-- Index all columns used in policy predicates
CREATE INDEX idx_team_members_user_id ON team_members(user_id);
CREATE INDEX idx_team_members_team_id ON team_members(team_id);
CREATE INDEX idx_documents_user_id ON documents(user_id);
CREATE INDEX idx_documents_org_id ON documents(org_id);

-- Composite indexes for common policy patterns
CREATE INDEX idx_team_members_team_user ON team_members(team_id, user_id);
```

Without indexes, every row check triggers a sequential scan.

---

## Secure Membership Pattern

```sql
-- 1. Lock down membership table
CREATE POLICY "membership_insert" ON team_members FOR INSERT
WITH CHECK (
  EXISTS (
    SELECT 1 FROM teams 
    WHERE teams.id = team_id 
    AND teams.owner_id = auth.uid()
  )
);

-- 2. Or use admin-only membership management
CREATE POLICY "membership_admin" ON team_members FOR ALL
USING (
  EXISTS (
    SELECT 1 FROM team_admins 
    WHERE team_admins.team_id = team_members.team_id 
    AND team_admins.user_id = auth.uid()
  )
);
```

---

## NULL Value Bypasses

### The NULL Comparison Trap

```sql
-- DANGEROUS: NULL comparisons return NULL (falsy), but...
CREATE POLICY "org_access" ON resources FOR SELECT
USING (org_id = (SELECT org_id FROM profiles WHERE user_id = auth.uid()));

-- If profile doesn't exist or org_id is NULL, comparison fails safely
-- BUT: What if resource.org_id is NULL?
```

### Secure NULL Handling

```sql
-- SECURE: Explicit NULL handling
CREATE POLICY "org_access" ON resources FOR SELECT
USING (
  org_id IS NOT NULL 
  AND org_id = (SELECT org_id FROM profiles WHERE user_id = auth.uid())
);
```

---

## JWT & Auth Claim Security

### Stale Claims Attack

```sql
-- DANGEROUS: JWT claims can be stale
CREATE POLICY "admin_access" ON admin_data FOR ALL
USING ((auth.jwt() ->> 'role') = 'admin');

-- User demoted but JWT still valid until expiry
```

### Secure Claim Verification

```sql
-- SECURE: Always verify against database state
CREATE POLICY "admin_access" ON admin_data FOR ALL
USING (
  EXISTS (
    SELECT 1 FROM user_roles 
    WHERE user_id = auth.uid() 
    AND role = 'admin'
    AND revoked_at IS NULL
  )
);
```

### auth.uid() vs JWT Claims

```sql
-- PREFER auth.uid() for identity
auth.uid()  -- Verified, consistent

-- AVOID raw JWT claims for authorization
auth.jwt() ->> 'sub'  -- Potentially confusing
auth.jwt() -> 'app_metadata' ->> 'role'  -- Can be stale
```

---

## SECURITY DEFINER Function Bypass

### The Privilege Escalation Pattern

`SECURITY DEFINER` runs the function as the **function owner**, not as a superuser. However, in Supabase, functions are typically owned by `postgres` which has `BYPASSRLS` privilege, effectively bypassing all RLS.

```sql
-- DANGEROUS: Runs as function owner (usually postgres with BYPASSRLS)
CREATE FUNCTION get_all_users() 
RETURNS SETOF users
LANGUAGE sql
SECURITY DEFINER  -- Bypasses RLS if owner has BYPASSRLS!
AS $$ SELECT * FROM users $$;
```

### Secure Function Pattern

```sql
-- SECURE: Use SECURITY INVOKER (default) or add explicit checks
CREATE FUNCTION get_user_data(target_user_id uuid)
RETURNS SETOF users
LANGUAGE sql
SECURITY INVOKER  -- RLS applies
AS $$ SELECT * FROM users WHERE id = target_user_id $$;

-- If SECURITY DEFINER needed, add manual auth:
CREATE FUNCTION admin_get_user(target_user_id uuid)
RETURNS users
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  -- Manual authorization check
  IF NOT EXISTS (
    SELECT 1 FROM user_roles 
    WHERE user_id = auth.uid() AND role = 'admin'
  ) THEN
    RAISE EXCEPTION 'Unauthorized';
  END IF;
  
  RETURN QUERY SELECT * FROM users WHERE id = target_user_id;
END;
$$;
```

---

## Views and RLS

### View Security Nuances

Views do NOT automatically bypass RLS. The actual risks are:

1. **Views owned by roles with `BYPASSRLS`** (like `postgres`) bypass RLS
2. **`SECURITY DEFINER` functions used inside views** can bypass RLS
3. **Missing `security_barrier`** allows optimizer to push user input into view, potentially leaking data via error messages

```sql
-- RISKY: View owned by postgres (has BYPASSRLS)
CREATE VIEW all_documents AS SELECT * FROM documents;

-- SAFER: View with security_barrier prevents optimization leaks
CREATE VIEW user_documents WITH (security_barrier = true) AS
SELECT * FROM documents WHERE user_id = auth.uid();

-- SAFEST: View owned by restricted role
SET ROLE authenticated;
CREATE VIEW user_documents AS SELECT * FROM documents WHERE user_id = auth.uid();
RESET ROLE;
```

---

## Realtime Subscription Gotchas

Realtime enforces RLS on database changes, but has unique behaviors:

1. **RLS still applies** — Client-side filters do NOT grant additional access
2. **Broadcast channel ignores RLS** — Anyone subscribed can broadcast to channel (not database-backed)
3. **Presence ignores RLS** — Presence metadata visible to all channel subscribers

**The real risk:** Overly permissive SELECT policies combined with Realtime expose more data in real-time. Broadcast and Presence are channel features, not database features—they bypass RLS because they don't touch the database.

### Secure Realtime Pattern

```sql
-- Enable RLS on realtime publication
ALTER PUBLICATION supabase_realtime ADD TABLE documents;

-- Ensure SELECT policy is strict (this IS enforced by Realtime)
CREATE POLICY "realtime_read" ON documents FOR SELECT
USING (auth.uid() = user_id);
```

**For Broadcast/Presence security:** Implement application-level authorization in Edge Functions or use Realtime's authorization callbacks.

---

## Edge Functions Security

### The service_role Danger

```typescript
// DANGEROUS: service_role in Edge Function
const supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);
// Bypasses ALL RLS — use only for admin operations

// SECURE: Use user's JWT
const supabase = createClient(url, process.env.SUPABASE_ANON_KEY, {
  global: { headers: { Authorization: req.headers.get('Authorization') } }
});
```

---

## Required Test Cases

For EVERY policy, test these scenarios:

### 1. Happy Path
- Authorized user can perform intended action

### 2. Negative Cases
- Unauthenticated user is blocked
- User from different org/team is blocked
- User with revoked permissions is blocked

### 3. Privilege Escalation
- Can user modify ownership fields?
- Can user INSERT as another user?
- Can user UPDATE to gain access to other rows?

### 4. Bypass Attempts
- NULL value injection
- Empty string injection
- Type confusion (if applicable)

### 5. Cross-Table Attacks
- Can user modify membership/relationship tables?
- Can user orphan rows to gain access?
- Can user exploit cascade deletes?

### Test Script Template

**NOTE: `SET LOCAL request.jwt.claims` only works in SQL editor/test environments. It does NOT work in production queries, Edge Functions, or client-side execution.**

```sql
-- Test as specific user (SQL EDITOR / TESTING ONLY)
SET LOCAL ROLE authenticated;
SET LOCAL request.jwt.claims = '{"sub": "user-uuid-here"}';

-- Attempt unauthorized access
SELECT * FROM documents WHERE user_id != 'user-uuid-here'; -- Should return empty

-- Attempt privilege escalation
UPDATE documents SET user_id = 'user-uuid-here' WHERE user_id = 'victim-uuid'; -- Should fail

-- Reset
RESET ROLE;
```

For production testing, use actual authenticated clients with different user tokens.

---

## Policy Review Checklist

Before approving ANY policy:

- [ ] RLS is enabled on table (`ALTER TABLE x ENABLE ROW LEVEL SECURITY`)
- [ ] Force RLS for table owners (`ALTER TABLE x FORCE ROW LEVEL SECURITY`)
- [ ] UPDATE policies have WITH CHECK
- [ ] INSERT policies validate ownership
- [ ] Ownership columns are immutable (trigger exists)
- [ ] No SECURITY DEFINER functions without manual auth
- [ ] JOIN-based auth uses locked-down membership tables
- [ ] NULL cases handled explicitly
- [ ] JWT claims verified against DB state for authorization
- [ ] Restrictive policies used for cross-cutting concerns
- [ ] Adversarial test cases written and passing

---

## Anti-Patterns to Reject

### Immediately Reject These Patterns

```sql
-- 1. Blanket access
WITH CHECK (true)
USING (true)

-- 2. Missing WITH CHECK on UPDATE
FOR UPDATE USING (auth.uid() = user_id)  -- No WITH CHECK

-- 3. Trusting JWT claims for authorization
USING ((auth.jwt() ->> 'role') = 'admin')

-- 4. Writable membership without validation
FOR INSERT WITH CHECK (true) -- on membership tables

-- 5. Mutable ownership without triggers
-- (any policy on table without immutability trigger)

-- 6. SECURITY DEFINER without manual auth
CREATE FUNCTION x() SECURITY DEFINER AS $$ ... $$  -- No auth check inside
```

---

## Secure Policy Templates

### Basic Ownership

```sql
-- Enable RLS
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;

-- Immutability trigger (REQUIRED)
CREATE OR REPLACE FUNCTION prevent_user_id_change()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.user_id IS DISTINCT FROM NEW.user_id THEN
    RAISE EXCEPTION 'Cannot modify user_id';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER documents_immutable_owner
  BEFORE UPDATE ON documents
  FOR EACH ROW EXECUTE FUNCTION prevent_user_id_change();

-- Policies
CREATE POLICY "select_own" ON documents FOR SELECT
USING (auth.uid() = user_id);

CREATE POLICY "insert_own" ON documents FOR INSERT
WITH CHECK (auth.uid() = user_id);

CREATE POLICY "update_own" ON documents FOR UPDATE
USING (auth.uid() = user_id)
WITH CHECK (auth.uid() = user_id);

CREATE POLICY "delete_own" ON documents FOR DELETE
USING (auth.uid() = user_id);
```

### Team-Based Access

```sql
-- Lock down team_members first
CREATE POLICY "members_read" ON team_members FOR SELECT
USING (user_id = auth.uid());

CREATE POLICY "members_insert" ON team_members FOR INSERT
WITH CHECK (
  EXISTS (
    SELECT 1 FROM teams 
    WHERE id = team_id AND owner_id = auth.uid()
  )
);

CREATE POLICY "members_delete" ON team_members FOR DELETE
USING (
  EXISTS (
    SELECT 1 FROM teams 
    WHERE id = team_id AND owner_id = auth.uid()
  )
);

-- Then projects use secure membership check
CREATE POLICY "projects_team_access" ON projects FOR SELECT
USING (
  EXISTS (
    SELECT 1 FROM team_members
    WHERE team_members.team_id = projects.team_id
    AND team_members.user_id = auth.uid()
  )
);
```

### Soft Delete Pattern

```sql
-- Restrictive policy for soft delete
CREATE POLICY "not_deleted" ON documents FOR SELECT AS RESTRICTIVE
USING (deleted_at IS NULL);

-- Permissive policies as normal
CREATE POLICY "owner_read" ON documents FOR SELECT
USING (auth.uid() = user_id);
```

---

## Policy Naming Convention

Use consistent naming for easier audits and debugging:

```sql
-- Pattern: rls_{operation}_{scope}
CREATE POLICY "rls_select_owner" ON documents FOR SELECT ...
CREATE POLICY "rls_insert_owner" ON documents FOR INSERT ...
CREATE POLICY "rls_update_owner" ON documents FOR UPDATE ...
CREATE POLICY "rls_delete_owner" ON documents FOR DELETE ...

-- For team/org-based access
CREATE POLICY "rls_select_team_member" ON projects FOR SELECT ...
CREATE POLICY "rls_select_org_member" ON resources FOR SELECT ...

-- For restrictive policies
CREATE POLICY "rls_restrict_not_deleted" ON documents FOR SELECT AS RESTRICTIVE ...
CREATE POLICY "rls_restrict_active_only" ON users FOR SELECT AS RESTRICTIVE ...
```

---

## When Generating Policies

1. **Ask clarifying questions** about ownership model, team structure, admin roles
2. **Generate immutability triggers FIRST** before any policies
3. **Include test cases** with every policy
4. **Document threat model** — what attacks does this prevent?
5. **Flag remaining risks** — what's still the application's responsibility?

## When Reviewing Policies

1. **Run the pre-flight checklist** to understand current state
2. **Trace execution paths** for each operation type
3. **Attempt bypass scenarios** mentally or in test environment
4. **Check for missing components** (triggers, WITH CHECK, etc.)
5. **Verify related tables** are also secured
