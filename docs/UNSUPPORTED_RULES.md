# Unsupported Wazuh rules (MiniWazuh)

Rules the pinned Wazuh 4.14.9 ruleset defines that MiniWazuh does not evaluate, because
they use a construct this reimplementation does not model. They are flagged, never
silently skipped (builder brief file 04 §2). MiniWazuh fidelity is **unverified** until a
one-time `wazuh-logtest` calibration (`tools/calibrate_wazuh.sh`).

- Total rules loaded: **469**, supported **444**.
- Claimed groups (sources our emitters produce): **402/420 = 95.7%**.

Unsupported constructs seen: `regex` (OS_Regex this translator rejects), `list` (CDB
lists), `if_fts` (first-time-seen), `check_diff`, `if_group`, `compiled_rule`, and rule
variables such as `$BAD_WORDS`.

| Rule | Group | Reason | Description |
|------|-------|--------|-------------|
| 501 | ossec | if_fts | New wazuh agent connected. |
| 533 | ossec | check_diff | Listened ports status (netstat) changed (new port opened or closed). |
| 534 | ossec | check_diff | List of logged in users. It will not be alerted by default. |
| 535 | ossec | check_diff | List of the last logged in users. |
| 1002 | syslog,errors | match:variable | Unknown problem somewhere in the system. |
| 5303 | syslog,su | regex | User successfully changed UID to root. |
| 5304 | syslog,su | regex | User successfully changed UID. |
| 5305 | syslog,su | if_fts | First time (su) is executed by user. |
| 5403 | syslog,sudo | if_fts | First time user executed sudo. |
| 10100 | syslog,fts | if_fts,if_group | First time user logged in. |
| 31102 | web,accesslog | compiled_rule | Ignored extensions on 400 error codes. |
| 31108 | web,accesslog | compiled_rule | Ignored URLs (simple queries). |
| 31109 | web,accesslog | url:regex | MSSQL Injection attempt (/ur.php, urchin.js) |
| 31140 | web,accesslog | compiled_rule | Ignoring google/msn/yahoo bots. |
| 31166 | web,accesslog | regex | Shellshock attack attempt |
| 31167 | web,accesslog | regex | Shellshock attack attempt |
| 31168 | web,accesslog | regex | Shellshock attack detected |
| 31169 | web,accesslog | regex | Shellshock attack detected |
| 80780 | audit | list | Audit: Watch - Write access. |
| 80783 | audit | list | Audit: Watch - Read access. |
| 80786 | audit | list | Audit: Watch - Change attribute. |
| 80789 | audit | list | Audit: Watch - Execute access: $(audit.file.name). |
| 80790 | audit | if_group | Audit: Created: $(audit.file.name). |
| 80791 | audit | if_group | Audit: Deleted: $(audit.file.name). |
| 80792 | audit | list | Audit: Command: $(audit.exe). |
