# Training Control — production deployment

## Current status
The published GitHub Pages and Android APK are **offline demonstrations**. They are NOT a production system. Do not enter actual employee information, pilot licences, medical records or passwords in the demo.

The SQL migration in `supabase/migrations/20261025_initial.sql` is the first **backend foundation**, not a completed deployment. It has not been applied or tested against a live Supabase project.

## Required deployment steps
1. Obtain company IT/security approval for the hosting location, retention policy and handling of medical certificates. Decide between a company-managed PostgreSQL/Supabase-compatible service and a managed cloud instance.
2. Provision an isolated production database and authentication service with HTTPS, backups, monitoring, MFA for privileged roles, and restricted administrative access.
3. Run the SQL migration in a **staging** database first; verify PostgreSQL and Supabase Storage policy compatibility.
4. Create the first manager identity in Supabase Auth through an authorized admin, then insert its UUID into `public.profiles` with `role='manager'`. Do this from the secure SQL console only.
5. Build the secure web/Android client against the project URL and **public publishable/anon key only**. Never commit the service role key.
6. Implement user invitations, authentication and secure session handling, upload validation, signed downloads, staff suspension, review and editing audit, backups, exports, multi-leg duty calculations, and tests.
7. Test role-based access in separate accounts: Training Manager, admin, instructor, pilot and blocked staff. Verify blocked sessions cannot read or write after revocation. Verify private documents cannot be accessed via guessing URLs.
8. Run a pilot trial with synthetic data, have company IT/security approve the system, then migrate authorized real data.

## Role policy
- **Training Manager**: sole manager role, can grant/revoke admin, instructor and pilot access. The manager account cannot be downgraded by ordinary administrators.
- **Admin**: review submitted flights and manage training and documents; cannot create or revoke other administrators.
- **Instructor**: view authorized assigned training/pilot data.
- **Pilot**: view own profile and submit own flight records.

## Time semantics
- BLOCK TIME = on-block UTC − off-block UTC.
- FLIGHT TIME = landing UTC − takeoff UTC.
- BLOCK NIGHT and FLIGHT NIGHT are manually entered minute totals, with validation against their corresponding totals.
- Night totals are subsets of block/flight time, not additional flight time.
- Multi-leg duty calculations and historical flight totals require further implementation.

## Security limitations in this initial schema
- Crew minimum and roles are enforced when a flight is approved, not while its draft/pending crew rows are being entered.
- A real invitation and account provisioning service, upload/document cleanup workflow, full immutable audit coverage, and frontend backend integration are **not yet implemented**.
- Database grants and row-level policies must be verified with an automated staging security test suite before production use.
