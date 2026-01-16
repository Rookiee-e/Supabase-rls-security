## What This Does

- Audits Supabase Row Level Security (RLS) policies for real-world security flaws  
- Identifies privilege escalation paths before attackers do  
- Prevents silent data leaks caused by permissive or mis-composed policies  
- Enforces correct use of `USING` vs `WITH CHECK` for UPDATE and INSERT  
- Protects against ownership hijacking (`user_id`, `org_id` tampering)  
- Detects insecure JOIN-based authorization patterns  
- Flags unsafe reliance on JWT claims for authorization  
- Identifies `SECURITY DEFINER` and `service_role` RLS bypass risks  
- Accounts for Supabase-specific behavior (Realtime, Edge Functions, roles)  
- Provides adversarial test cases, not just happy-path examples  
- Acts as a security checklist for reviewing existing RLS, not just writing new ones  

This is a **security audit framework**, not a tutorial.  
Its goal is to make RLS failures obvious **before they reach production**.

---

## Why This Exists

Most Supabase RLS examples:

- Look correct but are exploitable
- Ignore UPDATE + `WITH CHECK` privilege escalation
- Trust JWT claims that can become stale
- Allow ownership columns to be modified
- Miss join-table attack vectors
- Break under Realtime or Edge Function usage
- Fail silently instead of loudly

RLS is **behavioral, not declarative**.  
Security depends on how policies **compose and execute**, not how they look in isolation.

This repository documents **how RLS actually fails in production** and how to defend against those failures.

---

## What This Covers

- Correct mental model for RLS evaluation
- `USING` vs `WITH CHECK` and why missing checks are dangerous
- Ownership immutability and why policies alone are insufficient
- INSERT ownership injection attacks
- Multi-policy OR behavior vs RESTRICTIVE AND logic
- Join-based authorization vulnerabilities
- NULL comparison bypasses
- JWT staleness and database-verified authorization
- `SECURITY DEFINER` function risks
- View and function interaction with RLS
- Realtime subscription edge cases
- Edge Function authentication pitfalls
- Mandatory adversarial test cases

---

## Intended Audience

- Teams using Supabase in production
- Developers building multi-tenant applications
- Security-conscious backend engineers
- Anyone reviewing or auditing RLS policies
- Teams that have been “burned” by silent RLS failures

If your application relies on RLS for isolation, this guide should be treated as **required reading**.

---

## Philosophy

- Assume every policy is insecure until proven otherwise
- Think like an attacker, not a developer
- Never trust “it looks right”
- Test negative and adversarial paths first
- Prefer explicit denial over implicit allowance
- Fail loudly, not silently
