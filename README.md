# ad-password-hunter

LDAP-based tool for hunting exposed passwords hidden in Active Directory user attributes, for auditing and hardening AD environment.

Admins commonly leave temporary passwords, onboarding notes, or credential hints in free-text fields such as description, info (shown as "Notes" on the Telephones tab in ADUC), email, web page, and address fields. These fields are readable by any authenticated domain user by default, making them a common source of credential exposure and lateral movement during real attacks.

## Usage

```bash
python3 hunt_ad_passwords.py -server dc.domain.local -user 'user@domain.local' -password '<password>' -base-dn 'DC=domain,DC=local'
```

You'll be prompted for two things before it connects:

1. **Aggressive mode** — scan every readable attribute instead of the curated default list. Flags more, including more false positives.
2. **Known domain(s)** — comma-separated list of your organization's real email domains (e.g. `domain.local,corp.domain.local`), so normal `user@domain.local` addresses aren't flagged just for containing an `@`.

## Default fields checked

`info`, `description`, `physicalDeliveryOfficeName` (Office), `mail` (E-mail), `wWWHomePage` (Web page), `streetAddress`, `postOfficeBox`, `l` (City), `st` (State), `postalCode`, `telephoneNumber`, `homePhone`, `mobile`, `pager`, `facsimileTelephoneNumber`, `ipPhone`

In aggressive mode, every attribute is checked except a blacklist of binary/operational fields (SIDs, GUIDs, timestamps, security descriptors, etc.) that would otherwise produce noise.

## Detection heuristics

Any one of the following flags a value:

| Heuristic | Catches |
|---|---|
| keyword | pass, pwd, secret, credential, welcome123, changeme, letmein, api_key, token, etc. |
| strong-password-shape | mixed case + digit + symbol, 8+ chars |
| passphrase-shape | mixed case + digit, no symbol required |
| alnum-shape | letters + digits, any case, 6+ chars (e.g. test123) |
| dashed-passphrase | 3+ hyphen/underscore-separated word segments |
| camelcase-words | 2+ concatenated capitalized words, no digit/symbol needed (e.g. BinaisBesi) |
| user:pass-style | key:value or key=value style strings |
| base64-blob | base64-looking string that decodes cleanly to text |
| common-weak-password | known weak base words (password, qwerty, admin, welcome, iloveyou, etc.) |
| leetspeak-shape | substitution-style passwords (P@ssw0rd, adm1n) |
| word+year-shape | word + year suffix (Summer2024, Winter23!) |
| keyboard-walk | keyboard-adjacent patterns (qwerty, asdf, 1qaz2wsx) |
| special-char-complex | letter/digit + special character, 5+ chars |
| symbol+digit | digit + special character combo, no letters required |

## Extracting attributes manually (alternative)

```bash
ldapsearch -h dc.domain.local -D 'ldap@domain.local' -w '<password>' -b "DC=domain,DC=local" | less
```

This script automates hunting through the output of a query like the one above across every user object, instead of reading it manually.

## Reporting notes

Findings here typically map to:

- CWE-256 - Unprotected Storage of Credentials
- CWE-522 - Insufficiently Protected Credentials

Remediation: remove any credential material from free-text AD attributes, rotate the exposed credential immediately (assume it has been seen), and use a proper secrets manager or documented onboarding process instead.

## Disclaimer

For use only in authorized security testing and hardening reviews of environments you own or have explicit permission to assess.
