import os
import sys
import socket
import ssl
import subprocess
import platform
import datetime
import re
import json
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    print("Le module 'requests' est requis. Installe-le avec : pip install requests")
    sys.exit(1)

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("Le module 'colorama' est requis. Installe-le avec : pip install colorama")
    sys.exit(1)




GREEN = Fore.GREEN
CYAN = Fore.CYAN
RED = Fore.RED
YELLOW = Fore.YELLOW
WHITE = Fore.WHITE
MAGENTA = Fore.MAGENTA
RESET = Style.RESET_ALL
BOLD = Style.BRIGHT

BANNER = f"""{GREEN}{BOLD}
 ____                        ____ _     ___
|  _ \\ ___  ___ ___  _ __   / ___| |   |_ _|
| |_) / _ \\/ __/ _ \\| '_ \\ | |   | |    | |
|  _ <  __/ (_| (_) | | | || |___| |___ | |
|_| \\_\\___|\\___\\___/|_| |_| \\____|_____|___|
{RESET}{CYAN}        Recon & Security Audit Toolkit{RESET}
{YELLOW}   Usage légal uniquement - voir /whoami{RESET}
"""

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 587: "SMTP-Sub", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB"
}

SENSITIVE_PATHS = [
    "robots.txt", "sitemap.xml", "humans.txt", "crossdomain.xml",
    ".well-known/security.txt", "README.md", "CHANGELOG.md", "LICENSE",
    ".env", ".env.local", ".env.production", ".env.example",
    ".git/config", ".git/HEAD", ".svn/entries", ".idea/workspace.xml", ".vscode/settings.json",
    "config.php.bak", "config.json", "config.yml", "config.yaml", "web.config",
    "wp-config.php.bak", "wp-config.php.old", "wp-content/debug.log",
    "docker-compose.yml", "Dockerfile", ".dockerignore",
    "package.json", "package-lock.json", "composer.json", "composer.lock", ".npmrc",
    "database.sql", "dump.sql", "backup.sql", "db_backup.sql",
    "backup.zip", "backup.tar.gz", "backup.tar", "site.zip", "www.zip", "old.zip",
    "id_rsa", ".ssh/id_rsa", ".aws/credentials", ".docker/config.json", ".htpasswd",
    ".htaccess", "server-status", "server-info", "phpinfo.php", "info.php", "test.php",
    "install.php", "setup.php", "upgrade.php", "adminer.php", "xmlrpc.php",
    "admin/", "administrator/", "login/", "login.php", "wp-admin/", "wp-login.php",
    "phpmyadmin/", "pma/", "cpanel/", "webmail/",
    "api/", "api/v1/", "api/v2/", "api/docs", "swagger.json", "swagger-ui.html",
    "graphql", "graphiql",
    "old/", "test/", "temp/", "tmp/", "dev/", "staging/", "backup/",
    "vendor/", "node_modules/.package-lock.json",
    "error_log", "debug.log", "access.log", "logs/error.log"
]

SUBDOMAIN_WORDLIST = [
    "www", "mail", "webmail", "ftp", "admin", "administrator", "api", "dev",
    "staging", "test", "demo", "beta", "blog", "shop", "store", "cdn", "static",
    "media", "images", "img", "assets", "vpn", "portal", "remote", "secure",
    "app", "apps", "mobile", "m", "cpanel", "autodiscover", "server", "git",
    "gitlab", "github", "jenkins", "ci", "docs", "support", "help", "status",
    "monitor", "monitoring", "grafana", "kibana", "db", "database", "sql",
    "mysql", "redis", "backup", "old", "new", "ns1", "ns2", "ns3", "smtp",
    "smtp2", "pop", "imap", "mx", "proxy", "dashboard", "console", "internal",
    "intranet", "extranet", "test1", "test2", "preprod", "prod", "production",
    "sandbox", "lab", "labs", "dl", "download", "downloads", "upload", "files",
    "wiki", "confluence", "jira", "sso", "auth", "login", "id", "accounts",
    "cloud", "s3", "webdav", "ws", "socket", "ws1", "chat", "video", "stream"
]

OUTDATED_HINTS = [
    (re.compile(r"apache/2\.[0-2]", re.I), "Apache 2.0-2.2 est EOL depuis longtemps — vulnérabilités connues, vérifie NVD."),
    (re.compile(r"apache/2\.4\.([0-9]|[1-2][0-9])\b", re.I), "Version Apache 2.4 potentiellement ancienne — vérifie la dernière version stable."),
    (re.compile(r"nginx/1\.(0|[1-9])\.", re.I), "Version nginx ancienne détectée — vérifie les CVE associées."),
    (re.compile(r"php/5", re.I), "PHP 5.x est EOL (fin de support en 2019) — mise à jour fortement recommandée."),
    (re.compile(r"php/7\.[0-3]", re.I), "PHP 7.0-7.3 est EOL — mise à jour recommandée."),
    (re.compile(r"openssh[_/]?[5-6]\.", re.I), "Version OpenSSH ancienne — vérifie les CVE connues pour cette branche."),
    (re.compile(r"microsoft-iis/[1-7]\.", re.I), "Version IIS ancienne — vérifie les CVE associées."),
    (re.compile(r"wordpress\s*([0-4]\.|5\.[0-4])", re.I), "Version WordPress ancienne — de nombreuses failles connues existent sur ces versions."),
]

MAX_THREADS_PORTS = 200
MAX_THREADS_DIRS = 30
MAX_THREADS_SUBS = 50


def clear_screen():
    os.system("cls" if platform.system() == "Windows" else "clear")


def print_banner():
    clear_screen()
    print(BANNER)


def log_ok(msg):
    print(f"{GREEN}[+]{RESET} {msg}")


def log_info(msg):
    print(f"{CYAN}[*]{RESET} {msg}")


def log_warn(msg):
    print(f"{YELLOW}[!]{RESET} {msg}")


def log_err(msg):
    print(f"{RED}[-]{RESET} {msg}")


def normalize_target(target):
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        parsed_host = target
        url = "https://" + target
    else:
        parsed_host = urlparse(target).netloc
        url = target
    return parsed_host, url


def confirm_authorization(target):
    print(f"\n{YELLOW}{BOLD}⚠ AVERTISSEMENT LÉGAL{RESET}")
    print(f"{YELLOW}Tu confirmes être propriétaire de '{target}' ou disposer d'une")
    print(f"autorisation explicite pour le tester ?{RESET}")
    resp = input(f"{WHITE}Tape 'OUI' pour continuer : {RESET}").strip().upper()
    return resp == "OUI"


def check_outdated(banner_or_header):
    hints = []
    for pattern, msg in OUTDATED_HINTS:
        if pattern.search(banner_or_header):
            hints.append(msg)
    return hints




def mod_ping(host):
    log_info(f"Ping de {host}...")
    param = "-n" if platform.system() == "Windows" else "-c"
    try:
        result = subprocess.run(
            ["ping", param, "4", host],
            capture_output=True, text=True, timeout=15
        )
        print(result.stdout)
        if result.returncode == 0:
            log_ok("Hôte joignable.")
        else:
            log_warn("Hôte injoignable ou ICMP bloqué.")
    except Exception as e:
        log_err(f"Erreur ping : {e}")


def mod_whois(host):
    log_info(f"Recherche WHOIS pour {host}...")
    try:
        import whois
    except ImportError:
        log_warn("Installation du module 'python-whois'...")
        subprocess.run([sys.executable, "-m", "pip", "install", "python-whois",
                         "--break-system-packages", "-q"])
        import whois
    try:
        data = whois.whois(host)
        for key in ["domain_name", "registrar", "creation_date",
                    "expiration_date", "name_servers", "emails"]:
            val = data.get(key) if isinstance(data, dict) else getattr(data, key, None)
            if val:
                print(f"  {CYAN}{key}{RESET}: {val}")
    except Exception as e:
        log_err(f"Erreur WHOIS : {e}")


def mod_dns(host):
    log_info(f"Résolution DNS pour {host}...")
    try:
        addr_info = socket.getaddrinfo(host, None)
        ips = sorted(set(info[4][0] for info in addr_info))
        for ip in ips:
            log_ok(f"Adresse IP : {ip}")
    except Exception as e:
        log_err(f"Résolution impossible : {e}")

    try:
        import dns.resolver
        for rtype in ["MX", "NS", "TXT"]:
            try:
                answers = dns.resolver.resolve(host, rtype)
                for rdata in answers:
                    print(f"  {CYAN}{rtype}{RESET}: {rdata.to_text()}")
            except Exception:
                pass
    except ImportError:
        log_warn("Module 'dnspython' non installé (MX/NS/TXT ignorés). "
                  "Installe avec: pip install dnspython")




def grab_banner(ip, port, timeout=1.5):
    """Tente de récupérer une bannière de service (SSH/FTP/SMTP) ou un header HTTP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        banner = b""
        try:
            sock.settimeout(timeout)
            banner = sock.recv(256)
        except socket.timeout:
            pass

        if not banner:
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip.encode())
                banner = sock.recv(512)
            except Exception:
                pass

        sock.close()
        decoded = banner.decode(errors="ignore").strip().replace("\r\n", " | ")
        server_match = re.search(r"Server:\s*([^\r\n|]+)", decoded, re.I)
        if server_match:
            return server_match.group(1).strip()
        return decoded[:80] if decoded else None
    except Exception:
        return None


def scan_one_port(ip, port, name, grab=True):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.6)
    result = sock.connect_ex((ip, port))
    sock.close()
    if result != 0:
        return None
    banner = grab_banner(ip, port) if grab else None
    return (port, name, banner)


def mod_port_scan(host, full=False):
    mode_txt = "COMPLET (1-65535)" if full else "étendu (1-1024 + ports courants)"
    log_info(f"Scan de ports {mode_txt} sur {host} (multi-thread, banner grabbing)...")
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        log_err(f"Impossible de résoudre {host} : {e}")
        return []

    if full:
        ports_to_scan = {p: COMMON_PORTS.get(p, "?") for p in range(1, 65536)}
        log_warn("Scan complet 1-65535 : cela peut prendre plusieurs minutes.")
    else:
        ports_to_scan = dict(COMMON_PORTS)
        ports_to_scan.update({p: "?" for p in range(1, 1025) if p not in ports_to_scan})

    open_ports = []
    total = len(ports_to_scan)
    done = 0
    with ThreadPoolExecutor(max_workers=MAX_THREADS_PORTS) as executor:
        futures = {executor.submit(scan_one_port, ip, p, n): p for p, n in ports_to_scan.items()}
        for future in as_completed(futures):
            done += 1
            if done % 2000 == 0:
                log_info(f"... {done}/{total} ports testés")
            res = future.result()
            if res:
                port, name, banner = res
                if banner:
                    log_ok(f"Port {port}/{name} OUVERT — bannière : {banner}")
                    for hint in check_outdated(banner):
                        log_warn(f"  -> {hint}")
                else:
                    log_ok(f"Port {port}/{name} OUVERT")
                open_ports.append(port)

    if not open_ports:
        log_info("Aucun port ouvert détecté.")
    else:
        log_info(f"Total : {len(open_ports)} port(s) ouvert(s).")
    return sorted(open_ports)




def mod_http_headers(url):
    log_info(f"Analyse des en-têtes HTTP pour {url}...")
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True)
        headers = resp.headers
        print(f"  {CYAN}Status{RESET}: {resp.status_code}")
        server_hdr = headers.get('Server', 'non divulgué')
        print(f"  {CYAN}Serveur{RESET}: {server_hdr}")
        for hint in check_outdated(server_hdr):
            log_warn(hint)

        security_headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Frame-Options": "Anti-clickjacking",
            "X-Content-Type-Options": "Anti-MIME-sniffing",
            "Referrer-Policy": "Referrer Policy",
            "Permissions-Policy": "Permissions Policy",
        }
        for header, desc in security_headers.items():
            if header in headers:
                log_ok(f"{desc} présent : {headers[header][:60]}")
            else:
                log_warn(f"{desc} ABSENT ({header})")
        return resp
    except Exception as e:
        log_err(f"Erreur requête HTTP : {e}")
        return None


def mod_http_deep(url):
    log_info(f"Vérifications HTTP avancées (CORS, cookies, méthodes) pour {url}...")

    # Méthodes HTTP autorisées
    try:
        resp = requests.options(url, timeout=8)
        allow = resp.headers.get("Allow")
        if allow:
            log_info(f"Méthodes autorisées (OPTIONS) : {allow}")
            dangerous = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT"] if m in allow.upper()]
            if dangerous:
                log_warn(f"Méthodes potentiellement risquées activées : {', '.join(dangerous)}")
        else:
            log_info("Aucun header 'Allow' retourné sur OPTIONS.")
    except Exception as e:
        log_err(f"Erreur OPTIONS : {e}")

    # CORS
    try:
        resp = requests.get(url, headers={"Origin": "https://evil-test-origin.example"}, timeout=8)
        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac = resp.headers.get("Access-Control-Allow-Credentials")
        if acao:
            if acao == "*" and acac and acac.lower() == "true":
                log_err(f"CORS mal configuré : ACAO='*' + credentials=true (risque élevé)")
            elif acao == "*":
                log_warn(f"CORS ouvert à tous (ACAO='*')")
            elif "evil-test-origin.example" in acao:
                log_err(f"CORS reflète l'origine sans validation : {acao}")
            else:
                log_ok(f"CORS restreint : {acao}")
        else:
            log_ok("Aucun header CORS renvoyé (pas de partage cross-origin explicite).")
    except Exception as e:
        log_err(f"Erreur test CORS : {e}")

    # Cookies
    try:
        resp = requests.get(url, timeout=8)
        raw_cookies = []
        try:
            raw_cookies = resp.raw.headers.getlist("Set-Cookie")
        except Exception:
            sc = resp.headers.get("Set-Cookie")
            if sc:
                raw_cookies = [sc]

        if not raw_cookies:
            log_info("Aucun cookie détecté sur la page d'accueil.")
        for cookie in raw_cookies:
            name = cookie.split("=")[0]
            flags = []
            if "secure" not in cookie.lower():
                flags.append("Secure manquant")
            if "httponly" not in cookie.lower():
                flags.append("HttpOnly manquant")
            if "samesite" not in cookie.lower():
                flags.append("SameSite manquant")
            if flags:
                log_warn(f"Cookie '{name}' : {', '.join(flags)}")
            else:
                log_ok(f"Cookie '{name}' : flags de sécurité OK")
    except Exception as e:
        log_err(f"Erreur analyse cookies : {e}")


def mod_ssl_check(host):
    log_info(f"Vérification du certificat SSL/TLS pour {host}...")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                not_after = cert.get("notAfter")
                expire_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expire_date - datetime.datetime.utcnow()).days

                log_ok(f"Émis pour : {subject.get('commonName', 'N/A')}")
                log_ok(f"Émetteur : {issuer.get('organizationName', 'N/A')}")

                san = cert.get("subjectAltName", [])
                if san:
                    log_info(f"SAN : {', '.join(v for k, v in san)}")

                if days_left < 0:
                    log_err(f"Certificat EXPIRÉ depuis {abs(days_left)} jours")
                elif days_left < 30:
                    log_warn(f"Expire dans {days_left} jours")
                else:
                    log_ok(f"Valide encore {days_left} jours")

                protocol = ssock.version()
                log_info(f"Protocole négocié : {protocol}")
                if protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    log_err(f"Protocole obsolète et non sécurisé : {protocol}")
    except Exception as e:
        log_err(f"Erreur SSL : {e}")


def mod_tech_detect(url):
    log_info(f"Détection de technologies pour {url}...")
    try:
        resp = requests.get(url, timeout=10)
        headers = resp.headers
        html = resp.text.lower()

        techs = []
        if "x-powered-by" in headers:
            techs.append(headers["x-powered-by"])
        if "server" in headers:
            techs.append(headers["server"])

        signatures = {
            "wp-content": "WordPress",
            "joomla": "Joomla",
            "drupal": "Drupal",
            "shopify": "Shopify",
            "wix.com": "Wix",
            "cloudflare": "Cloudflare (CDN/WAF)",
            "react": "React",
            "next.js": "Next.js",
            "vue": "Vue.js",
            "laravel": "Laravel",
            "generator\" content=\"wordpress": "WordPress (meta generator)",
        }
        for sig, name in signatures.items():
            if sig in html:
                techs.append(name)

        # Version WordPress précise si présente
        wp_version = re.search(r'generator"\s*content="wordpress\s*([\d.]+)"', html)
        if wp_version:
            techs.append(f"WordPress {wp_version.group(1)}")
            for hint in check_outdated(f"wordpress {wp_version.group(1)}"):
                log_warn(hint)

        if techs:
            for t in sorted(set(techs)):
                log_ok(f"Détecté : {t}")
        else:
            log_info("Aucune technologie identifiable via signatures simples.")
    except Exception as e:
        log_err(f"Erreur détection : {e}")




def query_crtsh(domain):
    found = set()
    try:
        resp = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                names = entry.get("name_value", "")
                for n in names.split("\n"):
                    n = n.strip().lower()
                    if n and not n.startswith("*") and n.endswith(domain):
                        found.add(n)
    except Exception as e:
        log_warn(f"crt.sh indisponible ou erreur : {e}")
    return found


def resolve_sub(sub):
    try:
        ip = socket.gethostbyname(sub)
        return (sub, ip)
    except Exception:
        return None


def mod_subdomains(host):
    # Extraire le domaine racine (simplifié, sans lib externe de TLD parsing)
    parts = host.split(".")
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else host

    log_info(f"Recherche de sous-domaines pour {domain} via crt.sh (certificats publics)...")
    crt_subs = query_crtsh(domain)
    if crt_subs:
        log_ok(f"{len(crt_subs)} sous-domaine(s) trouvé(s) via crt.sh")
        for s in sorted(crt_subs)[:200]:
            print(f"  {CYAN}-{RESET} {s}")
    else:
        log_info("Aucun résultat via crt.sh.")

    log_info(f"Bruteforce DNS passif avec wordlist ({len(SUBDOMAIN_WORDLIST)} entrées)...")
    candidates = [f"{w}.{domain}" for w in SUBDOMAIN_WORDLIST]
    resolved = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS_SUBS) as executor:
        futures = [executor.submit(resolve_sub, c) for c in candidates]
        for future in as_completed(futures):
            res = future.result()
            if res:
                resolved.append(res)
                log_ok(f"{res[0]} -> {res[1]}")

    if not resolved:
        log_info("Aucun sous-domaine supplémentaire résolu via wordlist.")

    all_subs = crt_subs.union(r[0] for r in resolved)
    return sorted(all_subs)




def check_path(base, path):
    full_url = f"{base}/{path}"
    try:
        resp = requests.get(full_url, timeout=6, allow_redirects=False)
        return (path, resp.status_code)
    except Exception:
        return (path, None)


def mod_sensitive_files(url):
    log_info(f"Vérification de {len(SENSITIVE_PATHS)} fichiers/chemins sensibles sur {url}...")
    base = url.rstrip("/")
    found_any = False

    with ThreadPoolExecutor(max_workers=MAX_THREADS_DIRS) as executor:
        futures = [executor.submit(check_path, base, p) for p in SENSITIVE_PATHS]
        for future in as_completed(futures):
            path, status = future.result()
            if status == 200:
                log_warn(f"EXPOSÉ : /{path}  (200 OK)")
                found_any = True
            elif status in (301, 302, 403):
                log_info(f"/{path} -> {status}")

    if not found_any:
        log_ok("Aucun fichier sensible évident détecté parmi la liste testée.")




class ReportCapture:
    def __init__(self, path):
        self.path = path
        self.buffer = []

    def write(self, text):
        sys.__stdout__.write(text)
        self.buffer.append(re.sub(r"\x1b\[[0-9;]*m", "", text))

    def flush(self):
        sys.__stdout__.flush()

    def save(self):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("".join(self.buffer))


def run_full_report(host, url, full_port_scan=False):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"rapport_{host.replace('.', '_')}_{timestamp}.txt"
    filepath = os.path.join(os.getcwd(), filename)

    capture = ReportCapture(filepath)
    old_stdout = sys.stdout
    sys.stdout = capture
    try:
        print(f"=== RAPPORT RECONCLI - {host} - {datetime.datetime.now()} ===\n")
        print("\n--- PING ---")
        mod_ping(host)
        print("\n--- WHOIS ---")
        mod_whois(host)
        print("\n--- DNS ---")
        mod_dns(host)
        print("\n--- SOUS-DOMAINES ---")
        mod_subdomains(host)
        print("\n--- PORTS (+ banner grabbing) ---")
        mod_port_scan(host, full=full_port_scan)
        print("\n--- HEADERS HTTP ---")
        mod_http_headers(url)
        print("\n--- HTTP AVANCÉ (CORS/cookies/méthodes) ---")
        mod_http_deep(url)
        print("\n--- SSL/TLS ---")
        mod_ssl_check(host)
        print("\n--- TECHNOLOGIES ---")
        mod_tech_detect(url)
        print("\n--- FICHIERS SENSIBLES ---")
        mod_sensitive_files(url)
    finally:
        sys.stdout = old_stdout
        capture.save()
    log_ok(f"Rapport sauvegardé : {filepath}")




MENU = f"""
{MAGENTA}{BOLD}════════════════ MENU ════════════════{RESET}
 {WHITE}1{RESET}) Ping
 {WHITE}2{RESET}) WHOIS
 {WHITE}3{RESET}) DNS Lookup
 {WHITE}4{RESET}) Scan de ports étendu (1-1024, multi-thread + bannières)
 {WHITE}5{RESET}) Scan de ports COMPLET (1-65535, multi-thread + bannières)
 {WHITE}6{RESET}) En-têtes HTTP / sécurité
 {WHITE}7{RESET}) HTTP avancé (CORS, cookies, méthodes)
 {WHITE}8{RESET}) Certificat SSL/TLS
 {WHITE}9{RESET}) Détection de technologies
 {WHITE}10{RESET}) Fichiers/dossiers sensibles (~70 chemins)
 {WHITE}11{RESET}) Énumération de sous-domaines (crt.sh + wordlist)
 {WHITE}12{RESET}) Rapport complet (tous les modules -> .txt)
 {WHITE}0{RESET}) Changer de cible
 {WHITE}q{RESET}) Quitter
{MAGENTA}{BOLD}════════════════════════════════════════{RESET}
"""


def whoami():
    print_banner()
    print(f"""{WHITE}
ReconCLI est un outil de reconnaissance passive plus poussé (ports étendus,
banner grabbing, énumération de sous-domaines, tests CORS/cookies).
Il ne contient AUCUN exploit, AUCUN bruteforce de login, AUCUNE tentative
d'intrusion active. Toute utilisation contre une cible sans autorisation
explicite est de la seule responsabilité de l'utilisateur et peut constituer
une infraction pénale selon la loi applicable
(en France : art. 323-1 et suivants du Code pénal).
{RESET}""")
    input(f"\n{CYAN}Appuie sur Entrée pour revenir...{RESET}")


def main():
    print_banner()
    target = None
    host = None
    url = None

    while True:
        if not target:
            target = input(f"\n{WHITE}Entre une cible (domaine ou URL, ou 'whoami', ou 'q') : {RESET}").strip()
            if target.lower() == "q":
                break
            if target.lower() == "whoami":
                whoami()
                print_banner()
                target = None
                continue
            if not target:
                continue
            host, url = normalize_target(target)
            if not confirm_authorization(host):
                log_err("Autorisation non confirmée. Cible annulée.")
                target = None
                continue

        print_banner()
        log_info(f"Cible actuelle : {BOLD}{host}{RESET}")
        print(MENU)
        choice = input(f"{WHITE}Choix : {RESET}").strip().lower()

        print()
        if choice == "1":
            mod_ping(host)
        elif choice == "2":
            mod_whois(host)
        elif choice == "3":
            mod_dns(host)
        elif choice == "4":
            mod_port_scan(host, full=False)
        elif choice == "5":
            confirm = input(f"{YELLOW}Scan complet 1-65535, peut prendre plusieurs minutes. Continuer ? (o/n) : {RESET}").strip().lower()
            if confirm == "o":
                mod_port_scan(host, full=True)
        elif choice == "6":
            mod_http_headers(url)
        elif choice == "7":
            mod_http_deep(url)
        elif choice == "8":
            mod_ssl_check(host)
        elif choice == "9":
            mod_tech_detect(url)
        elif choice == "10":
            mod_sensitive_files(url)
        elif choice == "11":
            mod_subdomains(host)
        elif choice == "12":
            confirm = input(f"{YELLOW}Inclure le scan de ports COMPLET (1-65535) dans le rapport ? (o/n) : {RESET}").strip().lower()
            run_full_report(host, url, full_port_scan=(confirm == "o"))
        elif choice == "0":
            target = None
            continue
        elif choice == "q":
            break
        else:
            log_warn("Choix invalide.")

        input(f"\n{CYAN}Appuie sur Entrée pour continuer...{RESET}")

    print(f"\n{GREEN}À bientôt !{RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}Interrompu par l'utilisateur.{RESET}")
        sys.exit(0)