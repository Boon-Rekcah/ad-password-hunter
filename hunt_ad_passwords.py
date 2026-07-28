import argparse
import base64
import re
import sys

from ldap3 import Server, Connection, ALL, NTLM, SUBTREE

DEFAULT_ATTRS = [
    "info",
    "description",
    "physicalDeliveryOfficeName",
    "mail",
    "wWWHomePage",
    "streetAddress",
    "postOfficeBox",
    "l",
    "st",
    "postalCode",
    "telephoneNumber",
    "homePhone",
    "mobile",
    "pager",
    "facsimileTelephoneNumber",
    "ipPhone",
]

SKIP_ATTRS = {
    "objectclass", "objectguid", "objectsid", "whencreated", "whenchanged",
    "usncreated", "usnchanged", "instancetype", "distinguishedname", "cn",
    "name", "samaccountname", "useraccountcontrol", "primarygroupid",
    "samaccounttype", "lastlogon", "lastlogontimestamp", "lastlogoff",
    "pwdlastset", "badpwdcount", "badpasswordtime", "logoncount",
    "accountexpires", "dscorepropagationdata", "iscriticalsystemobject",
    "memberof", "member", "grouptype", "systemflags",
    "showinadvancedviewonly", "codepage", "countrycode", "admincount",
    "logonhours", "objectcategory", "dnshostname", "serviceprincipalname",
    "ridsetreferences", "serverreferencebl", "ntsecuritydescriptor",
    "replpropertymetadata", "replupToDatevector", "msds-supportedencryptiontypes",
    "lockouttime", "lastlogondate", "passwordlastset", "createtimestamp",
    "modifytimestamp", "msds-lastsuccessfulinteractivelogontime",
    "msds-lastfailedinteractivelogontime",
}

BUILTIN_DESCRIPTION_PATTERN = re.compile(
    r"(built-?in account for (administering|guest access)|"
    r"key distribution center service account|"
    r"a user account managed (by|and used) (the )?system|"
    r"account for providing remote assistance|"
    r"this is a vendor.?s account)",
    re.IGNORECASE,
)

EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9._%+\-]+@([A-Za-z0-9\-]+\.)+[A-Za-z]{2,}$"
)

DATETIME_LIKE_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}"
)

ZERO_EPOCH_PATTERN = re.compile(r"^1601-01-01")

KEYWORD_PATTERN = re.compile(
    r"(pass|pwd|pw:|contraseña|senha|secret|credential|cred\b|"
    r"welcome\d|changeme|letmein|initial|temp\s*pw|default\s*pw|"
    r"login\s*:|user\s*:|api[_-]?key|token)",
    re.IGNORECASE,
)

STRONG_PATTERN = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9\s]).{8,}$"
)

PASSPHRASE_PATTERN = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z0-9]{8,}$"
)

ALNUM_PATTERN = re.compile(
    r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9]{6,}$"
)

DASHED_WORDS_PATTERN = re.compile(
    r"^[A-Za-z0-9]+([-_][A-Za-z0-9]+){2,}$"
)

CAMELCASE_WORDS_PATTERN = re.compile(
    r"^([A-Z][a-z]+){2,}\d*$"
)

USERPASS_PATTERN = re.compile(
    r"[A-Za-z0-9_.\-]{2,}\s*[:=]\s*\S{4,}"
)

BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")

COMMON_WEAK_PATTERN = re.compile(
    r"(password|123456|qwerty|letmein|admin|welcome|changeme|iloveyou|"
    r"monkey|dragon|football|master|login|princess|solo|starwars|"
    r"passw0rd|p@ssword)\d*",
    re.IGNORECASE,
)

LEET_PATTERN = re.compile(
    r"^(?=.*[A-Za-z])(?=.*[@$0134])[A-Za-z0-9@$]{6,}$"
)

YEAR_SUFFIX_PATTERN = re.compile(
    r"^[A-Za-z]+(19|20)\d{2}[!@#$%^&*]?$"
)

KEYBOARD_WALK_PATTERN = re.compile(
    r"(qwerty|asdf|zxcv|1qaz2wsx|qazwsx|123qwe)",
    re.IGNORECASE,
)

SPECIAL_CHAR_COMPLEX_PATTERN = re.compile(
    r"^(?=.*[!@#$%^&*()_+\-=\[\]{};:'\",.<>/?\\|`~])"
    r"(?=.*[A-Za-z0-9]).{5,}$"
)

SYMBOL_DIGIT_PATTERN = re.compile(
    r"^(?=.*\d)(?=.*[!@#$%^&*()_+\-=]){4,}$"
)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-server", required=True, help="DC hostname or IP")
    parser.add_argument("-user", required=True, help="bind user, e.g. ldap@domain.local")
    parser.add_argument("-password", required=True, help="bind password")
    parser.add_argument("-base-dn", required=True, help='e.g. DC=support,DC=htb')
    parser.add_argument("-ldaps", action="store_true", help="use LDAPS instead of plain LDAP")
    parser.add_argument("-auth", choices=["ntlm", "simple"], default="simple")
    return parser.parse_args()


def ask_aggressive():
    print("\nBy default this checks a curated list of fields "
          "(info, description, office, email, web page, address fields, phone numbers).")
    answer = input(
        "Run in aggressive mode and scan ALL attributes instead? "
        "This can flag more false positives. (yes/no) [no]: "
    ).strip().lower()
    return answer in ("y", "yes")


def ask_known_domain():
    domains = input(
        "Domain name(s) to treat as normal for email addresses, e.g. "
        "support.htb or support.htb,corp.support.htb "
        "(comma-separated, leave blank to skip this filter): "
    ).strip()
    if not domains:
        return []
    return [d.strip().lower() for d in domains.split(",") if d.strip()]


def connect(args):
    server = Server(args.server, use_ssl=args.ldaps, get_info=ALL)
    if args.auth == "ntlm":
        conn = Connection(server, user=args.user, password=args.password, authentication=NTLM)
    else:
        conn = Connection(server, user=args.user, password=args.password)
    if not conn.bind():
        print(f"[!] Bind failed: {conn.result}")
        sys.exit(1)
    return conn


def looks_like_base64_secret(value):
    if not BASE64_PATTERN.match(value):
        return False
    try:
        decoded = base64.b64decode(value, validate=True)
        decoded.decode("utf-8")
        return True
    except Exception:
        return False


def is_noise_value(value, known_domains=None):
    if ZERO_EPOCH_PATTERN.match(value):
        return True
    if DATETIME_LIKE_PATTERN.match(value):
        return True
    if known_domains and EMAIL_PATTERN.match(value):
        value_lower = value.lower()
        for domain in known_domains:
            if value_lower.endswith("@" + domain):
                return True
    return False


def check_value(value, known_domains=None):
    if is_noise_value(value, known_domains):
        return []

    reasons = []
    if KEYWORD_PATTERN.search(value):
        reasons.append("keyword")
    if STRONG_PATTERN.match(value):
        reasons.append("strong-password-shape")
    if PASSPHRASE_PATTERN.match(value):
        reasons.append("passphrase-shape")
    if ALNUM_PATTERN.match(value):
        reasons.append("alnum-shape")
    if DASHED_WORDS_PATTERN.match(value):
        reasons.append("dashed-passphrase")
    if CAMELCASE_WORDS_PATTERN.match(value):
        reasons.append("camelcase-words")
    if USERPASS_PATTERN.search(value):
        reasons.append("user:pass-style")
    if looks_like_base64_secret(value):
        reasons.append("base64-blob")
    if COMMON_WEAK_PATTERN.search(value):
        reasons.append("common-weak-password")
    if LEET_PATTERN.match(value):
        reasons.append("leetspeak-shape")
    if YEAR_SUFFIX_PATTERN.match(value):
        reasons.append("word+year-shape")
    if KEYBOARD_WALK_PATTERN.search(value):
        reasons.append("keyboard-walk")
    if SPECIAL_CHAR_COMPLEX_PATTERN.match(value):
        reasons.append("special-char-complex")
    if SYMBOL_DIGIT_PATTERN.match(value):
        reasons.append("symbol+digit")
    return reasons


def hunt(conn, base_dn, aggressive, known_domains):
    attrs = ["*"] if aggressive else DEFAULT_ATTRS + ["sAMAccountName"]

    conn.search(
        search_base=base_dn,
        search_filter="(&(objectClass=user)(objectCategory=person))",
        search_scope=SUBTREE,
        attributes=attrs,
    )

    findings = []
    for entry in conn.entries:
        sam = str(entry.sAMAccountName) if "sAMAccountName" in entry else "?"
        target_attrs = entry.entry_attributes if aggressive else DEFAULT_ATTRS
        for attr in target_attrs:
            if aggressive and attr.lower() in SKIP_ATTRS:
                continue
            if attr not in entry:
                continue
            value = str(entry[attr])
            if not value or value in ("[]", "None"):
                continue
            if BUILTIN_DESCRIPTION_PATTERN.search(value):
                continue
            reasons = check_value(value, known_domains)
            if reasons:
                findings.append((sam, attr, value, reasons))
    return findings


def main():
    args = parse_args()
    aggressive = ask_aggressive()
    known_domains = ask_known_domain()
    conn = connect(args)
    findings = hunt(conn, args.base_dn, aggressive, known_domains)

    mode = "aggressive (all attributes)" if aggressive else "default (curated field list)"
    print(f"\n[i] Mode: {mode}\n")

    if not findings:
        print("[+] No password-like patterns found.")
        return

    print(f"[!] {len(findings)} potential exposure(s) found:\n")
    for sam, attr, value, reasons in findings:
        print(f"  user: {sam}")
        print(f"  attribute: {attr}")
        print(f"  value: {value}")
        print(f"  matched: {', '.join(reasons)}")
        print("-" * 40)


if __name__ == "__main__":
    main()
