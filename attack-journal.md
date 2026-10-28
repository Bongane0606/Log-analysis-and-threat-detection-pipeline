# Attack Journal

| Time (UTC/local) | Tool | Type | Target | Notes |
|---|---|---|---|---|
| 2026-10-22 ~09:4X | Hydra | Brute force | labuser@127.0.0.1 | wordlist.txt, 8 passwords |
| 2026-10-22 09:50 | Hydra | Password spraying | 127.0.0.1 | users.txt, 6 usernames, password1 |

## Normal traffic
- Manual logins as labuser (some correct, some mistyped) for baseline comparison.
| 2026-10-22 09:56 | sshpass loop | Slow brute force (evasion) | labuser@127.0.0.1 | 8 attempts, ~90s apart, wordlist.txt. No alert triggered — stayed under 5-in-5min threshold |
