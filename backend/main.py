#!/usr/bin/env python3
"""
VajraNet AI Vulnerability Scanner v5.4
FIXED: Soft-404 cluster detection | False positive elimination |
       Cloudflare crawler bypass | Score accuracy | Dedup report output
GPU: llama.cpp full VRAM offload | Windows | localhost:8080
"""

import os, sys, subprocess, socket, ssl, time, json, re, uuid
import urllib.parse, warnings, threading, random, hashlib, base64
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from datetime import datetime
from collections import deque, Counter
from urllib.robotparser import RobotFileParser
import requests
from bs4 import BeautifulSoup, Comment

warnings.filterwarnings('ignore')
try:
    import urllib3; urllib3.disable_warnings()
except: pass

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════════════════════════════
LLAMA_SERVER = r"C:\Users\amd\Documents\jarvis\llama.cpp\build\bin\Release\llama-server.exe"
MODEL_PATH   = r"C:\Users\amd\Documents\jarvis\llama.cpp\model\mistral\siya.gguf"
BATCH_SIZE   = "512"
CTX          = "9700"
THREADS      = 6
GPU_LAYERS   = 999
HTTP_PORT    = 8080
LLAMA_PORT   = 8081

NMAP_PATH    = "nmap"
NUCLEI_PATH  = "nuclei"
ZAP_API_URL  = None
ZAP_API_KEY  = ""

MAX_CRAWL_PAGES        = 60
MAX_CRAWL_DEPTH        = 3
CRAWL_SAME_DOMAIN_ONLY = True

# ── Soft-404 cluster detection config ─────────────────────────────────────
# If >= this fraction of all 200-OK path responses cluster within CLUSTER_BAND
# bytes of each other, treat the modal size as the soft-404 size.
CLUSTER_FRACTION = 0.55   # 55 % of 200-OK responses must cluster
CLUSTER_BAND     = 400    # ± 400 B around the mode

UA_LIST = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/111.0.0.0',
]

SEC_CH_UA_MAP = {
    'Chrome/125': '"Google Chrome";v="125","Chromium";v="125","Not.A/Brand";v="24"',
    'Chrome/124': '"Google Chrome";v="124","Chromium";v="124","Not.A/Brand";v="24"',
    'Chrome/123': '"Google Chrome";v="123","Chromium";v="123","Not.A/Brand";v="24"',
    'Firefox':    '"Firefox";v="126","Not.A/Brand";v="8"',
    'Edg':        '"Microsoft Edge";v="124","Chromium";v="124","Not.A/Brand";v="24"',
    'OPR':        '"Opera";v="111","Chromium";v="125","Not.A/Brand";v="24"',
    'Safari':     '"Safari";v="17","Not.A/Brand";v="8"',
    'Mobile':     '"Not.A/Brand";v="8","Chromium";v="125","Google Chrome";v="125"',
}

BASE_HDRS = {
    'Accept':                    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language':           'en-US,en;q=0.9',
    'Accept-Encoding':           'gzip, deflate, br',
    'Cache-Control':             'max-age=0',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Ch-Ua':                 '"Google Chrome";v="125","Chromium";v="125","Not.A/Brand";v="24"',
    'Sec-Ch-Ua-Mobile':          '?0',
    'Sec-Ch-Ua-Platform':        '"Windows"',
    'Sec-Fetch-Dest':            'document',
    'Sec-Fetch-Mode':            'navigate',
    'Sec-Fetch-Site':            'none',
    'Sec-Fetch-User':            '?1',
    'Connection':                'keep-alive',
    'DNT':                       '1',
    'Referer':                   'https://www.google.com/',
}

EXPECTED_PORTS = {25, 80, 110, 143, 443, 465, 587, 993, 995}

jobs_lock = threading.Lock()
scan_jobs  = {}
doc_store  = {}

# ══════════════════════════════════════════════════════════════════════════════
#  OWASP / CWE / MITRE MAPPING
# ══════════════════════════════════════════════════════════════════════════════
OWASP_MAP = {
    'sqli':             ('A03:2021 – Injection',                 'CWE-89',   'T1190'),
    'xss':              ('A03:2021 – Injection',                 'CWE-79',   'T1059.007'),
    'open_redirect':    ('A01:2021 – Broken Access Control',     'CWE-601',  'T1566'),
    'cors_wildcard':    ('A05:2021 – Security Misconfiguration', 'CWE-942',  'T1557'),
    'clickjacking':     ('A05:2021 – Security Misconfiguration', 'CWE-1021', 'T1056'),
    'missing_csp':      ('A05:2021 – Security Misconfiguration', 'CWE-693',  'T1059'),
    'missing_hsts':     ('A05:2021 – Security Misconfiguration', 'CWE-311',  'T1557'),
    'ssl_weak':         ('A02:2021 – Cryptographic Failures',    'CWE-326',  'T1557'),
    'ssl_expired':      ('A02:2021 – Cryptographic Failures',    'CWE-298',  'T1557'),
    'info_disclosure':  ('A05:2021 – Security Misconfiguration', 'CWE-200',  'T1082'),
    'exposed_git':      ('A05:2021 – Security Misconfiguration', 'CWE-312',  'T1552'),
    'exposed_env':      ('A05:2021 – Security Misconfiguration', 'CWE-312',  'T1552.001'),
    'exposed_config':   ('A05:2021 – Security Misconfiguration', 'CWE-312',  'T1552'),
    'exposed_backup':   ('A05:2021 – Security Misconfiguration', 'CWE-530',  'T1005'),
    'exposed_admin':    ('A01:2021 – Broken Access Control',     'CWE-284',  'T1078'),
    'cookie_no_secure': ('A02:2021 – Cryptographic Failures',    'CWE-614',  'T1557'),
    'cookie_no_http':   ('A05:2021 – Security Misconfiguration', 'CWE-1004', 'T1059'),
    'http_put':         ('A05:2021 – Security Misconfiguration', 'CWE-650',  'T1190'),
    'http_trace':       ('A05:2021 – Security Misconfiguration', 'CWE-16',   'T1557'),
    'dir_listing':      ('A05:2021 – Security Misconfiguration', 'CWE-548',  'T1083'),
    'open_port_db':     ('A05:2021 – Security Misconfiguration', 'CWE-200',  'T1046'),
    'mixed_content':    ('A02:2021 – Cryptographic Failures',    'CWE-319',  'T1557'),
    'csrf_missing':     ('A01:2021 – Broken Access Control',     'CWE-352',  'T1185'),
}

def get_owasp(key):
    return OWASP_MAP.get(key, ('A05:2021 – Security Misconfiguration','CWE-200','T1190'))

# ══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════
SEC_HEADERS = [
    'strict-transport-security','content-security-policy','x-frame-options',
    'x-content-type-options','x-xss-protection','referrer-policy',
    'permissions-policy','cross-origin-embedder-policy',
    'cross-origin-opener-policy','cross-origin-resource-policy',
]

PORTS = {
    21:    ('FTP',      'CRITICAL','Credential brute-force, anonymous login'),
    22:    ('SSH',      'HIGH',    'Brute-force if weak creds'),
    23:    ('Telnet',   'CRITICAL','Plaintext protocol — creds in cleartext'),
    25:    ('SMTP',     'HIGH',    'Open relay abuse, phishing pivot'),
    53:    ('DNS',      'MEDIUM',  'Zone transfer, DNS amplification'),
    80:    ('HTTP',     'MEDIUM',  'Unencrypted traffic — MITM possible'),
    110:   ('POP3',     'HIGH',    'Email credential interception'),
    143:   ('IMAP',     'HIGH',    'Email access — credential theft'),
    443:   ('HTTPS',    'LOW',     'Standard HTTPS — verify cipher'),
    445:   ('SMB',      'CRITICAL','EternalBlue / ransomware entry'),
    1433:  ('MSSQL',    'CRITICAL','DB exposed — full data exfiltration'),
    3306:  ('MySQL',    'CRITICAL','DB exposed — full data exfiltration'),
    3389:  ('RDP',      'CRITICAL','Remote Desktop — #1 ransomware entry'),
    5432:  ('PgSQL',    'CRITICAL','DB exposed — full data exfiltration'),
    6379:  ('Redis',    'CRITICAL','Often unauthenticated — memory dump'),
    8080:  ('HTTP-Alt', 'HIGH',    'Dev/admin panels, less hardened'),
    8443:  ('HTTPS-Alt','MEDIUM',  'Secondary HTTPS attack surface'),
    9200:  ('Elastic',  'CRITICAL','Often unauthenticated — data exposed'),
    27017: ('MongoDB',  'CRITICAL','Often unauthenticated — DB dump'),
}

PATHS = [
    ('/.env',                   'CRITICAL','Env secrets — API keys, DB passwords'),
    ('/.env.local',             'CRITICAL','Local env secrets'),
    ('/.env.production',        'CRITICAL','Production secrets'),
    ('/.env.backup',            'CRITICAL','Backup env file'),
    ('/.env.staging',           'HIGH',    'Staging secrets'),
    ('/.env.dev',               'HIGH',    'Dev secrets'),
    ('/admin',                  'HIGH',    'Admin interface'),
    ('/admin/',                 'HIGH',    'Admin interface'),
    ('/admin/login',            'HIGH',    'Admin login panel'),
    ('/admin.php',              'HIGH',    'PHP admin panel'),
    ('/administrator',          'HIGH',    'CMS admin panel'),
    ('/administrator/index.php','HIGH',    'Joomla admin'),
    ('/admin/config',           'CRITICAL','Admin config exposure'),
    ('/wp-admin',               'HIGH',    'WordPress admin'),
    ('/wp-config.php',          'CRITICAL','WordPress DB credentials'),
    ('/wp-login.php',           'HIGH',    'WordPress login — brute force target'),
    ('/xmlrpc.php',             'HIGH',    'WordPress XML-RPC — DDoS/auth bypass'),
    ('/wp-json/wp/v2/users',    'HIGH',    'WordPress user enumeration'),
    ('/phpmyadmin',             'CRITICAL','MySQL admin UI'),
    ('/pma',                    'CRITICAL','phpMyAdmin alias'),
    ('/adminer.php',            'CRITICAL','Adminer DB tool'),
    ('/dbadmin',                'CRITICAL','DB admin panel'),
    ('/backup',                 'CRITICAL','Backup directory'),
    ('/backup.zip',             'CRITICAL','Full site backup'),
    ('/backup.tar.gz',          'CRITICAL','Full site backup'),
    ('/backup.sql',             'CRITICAL','Database SQL dump'),
    ('/dump.sql',               'CRITICAL','Database SQL dump'),
    ('/db.sql',                 'CRITICAL','Database SQL dump'),
    ('/db_backup.zip',          'CRITICAL','Database backup'),
    ('/.git/config',            'CRITICAL','Git config — remote URLs, creds'),
    ('/.git/HEAD',              'HIGH',    'Git HEAD — confirms git exposure'),
    ('/.git/COMMIT_EDITMSG',    'HIGH',    'Git commit message'),
    ('/.git/index',             'CRITICAL','Git index — full file tree'),
    ('/.svn/entries',           'CRITICAL','SVN source code exposure'),
    ('/.svn/wc.db',             'CRITICAL','SVN working copy database'),
    ('/config.php',             'CRITICAL','PHP config — DB/API credentials'),
    ('/config.json',            'CRITICAL','JSON config — credentials'),
    ('/config.yaml',            'CRITICAL','YAML config — credentials'),
    ('/config.ini',             'HIGH',    'INI config — settings exposure'),
    ('/settings.php',           'CRITICAL','PHP settings — credentials'),
    ('/settings.py',            'HIGH',    'Python settings'),
    ('/local_settings.py',      'CRITICAL','Local dev settings — real creds'),
    ('/api/v1/users',           'HIGH',    'User data API — unauthorized enum'),
    ('/api/v2/users',           'HIGH',    'User data API'),
    ('/api/admin',              'CRITICAL','Admin API — privilege escalation'),
    ('/api/keys',               'CRITICAL','API keys endpoint'),
    ('/api/config',             'CRITICAL','API config — credentials'),
    ('/api/debug',              'HIGH',    'Debug endpoint — system info'),
    ('/swagger-ui.html',        'MEDIUM',  'Swagger UI — full API docs exposed'),
    ('/swagger.json',           'MEDIUM',  'Swagger spec — all endpoints'),
    ('/api-docs',               'MEDIUM',  'API documentation'),
    ('/openapi.json',           'MEDIUM',  'OpenAPI spec'),
    ('/actuator',               'HIGH',    'Spring Boot actuator'),
    ('/actuator/env',           'CRITICAL','Spring env — all secrets'),
    ('/actuator/dump',          'CRITICAL','Thread dump — memory inspection'),
    ('/actuator/logfile',       'HIGH',    'Application log'),
    ('/server-status',          'MEDIUM',  'Apache status page'),
    ('/server-info',            'MEDIUM',  'Apache info — module list'),
    ('/.htaccess',              'HIGH',    'Apache config'),
    ('/.htpasswd',              'CRITICAL','Apache password file — hashed creds'),
    ('/web.config',             'CRITICAL','IIS config — connection strings'),
    ('/error.log',              'HIGH',    'Error log — stack traces'),
    ('/access.log',             'MEDIUM',  'Access log — user activity'),
    ('/debug.log',              'HIGH',    'Debug log — sensitive data'),
    ('/laravel.log',            'HIGH',    'Laravel log — SQL queries'),
    ('/test.php',               'MEDIUM',  'Test file in production'),
    ('/info.php',               'HIGH',    'PHP info — full server config'),
    ('/phpinfo.php',            'HIGH',    'PHP info — full server config'),
    ('/debug.php',              'HIGH',    'Debug page — system info'),
    ('/console',                'HIGH',    'Web console — potential RCE'),
    ('/composer.json',          'MEDIUM',  'Dependency list — version fp'),
    ('/package.json',           'MEDIUM',  'Node.js deps — version fp'),
    ('/requirements.txt',       'MEDIUM',  'Python deps — version fp'),
    ('/.DS_Store',              'MEDIUM',  'macOS metadata — dir structure'),
    ('/.bash_history',          'CRITICAL','Shell history — commands, creds'),
    ('/.ssh/id_rsa',            'CRITICAL','PRIVATE SSH KEY — full server access'),
    ('/id_rsa',                 'CRITICAL','PRIVATE SSH KEY'),
    ('/server.key',             'CRITICAL','SSL private key'),
    ('/private.key',            'CRITICAL','Private key'),
    ('/shell.php',              'CRITICAL','PHP webshell — RCE'),
    ('/cmd.php',                'CRITICAL','Command execution webshell'),
    ('/c99.php',                'CRITICAL','C99 webshell — full RCE'),
    ('/r57.php',                'CRITICAL','r57 webshell — full RCE'),
    ('/crossdomain.xml',        'MEDIUM',  'Flash cross-domain policy'),
    ('/robots.txt',             'LOW',     'Robots.txt — hidden paths'),
    ('/sitemap.xml',            'LOW',     'Sitemap — URL enumeration'),
    ('/.well-known/security.txt','LOW',    'Security contact'),
]

# Content signatures — what a REAL response must contain
PATH_CONTENT_CHECKS = {
    '/.env':              ['APP_KEY=','DB_PASSWORD=','APP_ENV=','DB_HOST='],
    '/.env.local':        ['APP_KEY=','DB_PASSWORD=','APP_ENV='],
    '/.env.production':   ['APP_KEY=','DB_PASSWORD=','APP_ENV='],
    '/.env.backup':       ['APP_KEY=','DB_PASSWORD=','APP_ENV='],
    '/.env.staging':      ['APP_KEY=','DB_PASSWORD=','APP_ENV='],
    '/.env.dev':          ['APP_KEY=','DB_PASSWORD=','APP_ENV=','DB_HOST='],
    '/wp-config.php':     ['DB_NAME','DB_USER','DB_PASSWORD','table_prefix'],
    '/config.php':        ['<?php','password','database','host'],
    '/config.json':       ['"password"','"database"','"host"','"key"'],
    '/config.yaml':       ['password:','database:','host:'],
    '/config.ini':        ['password','database','host'],
    '/settings.php':      ['<?php','password','database'],
    '/settings.py':       ['DATABASE','PASSWORD','SECRET_KEY'],
    '/local_settings.py': ['DATABASE','PASSWORD','SECRET_KEY'],
    '/.git/config':       ['[core]','repositoryformatversion'],
    '/.git/HEAD':         ['ref: refs/heads/'],
    '/.git/index':        [],   # binary — size check only
    '/.svn/entries':      ['<?xml','svn:'],
    '/.svn/wc.db':        [],   # binary SQLite
    '/composer.json':     ['"require"','"name"'],
    '/package.json':      ['"name"','"version"'],
    '/robots.txt':        ['User-agent:','Disallow:'],
    '/sitemap.xml':       ['<urlset','<loc>'],
    '/phpinfo.php':       ['phpinfo','PHP Version'],
    '/info.php':          ['phpinfo','PHP Version'],
    '/.htaccess':         ['RewriteEngine','Options','Deny from'],
    '/.htpasswd':         [':$apr1$',':$2y$',':'],
    '/web.config':        ['<?xml','<configuration>'],
    '/adminer.php':       ['adminer','Adminer'],
    '/swagger.json':      ['"swagger"','"openapi"','"paths"'],
    '/openapi.json':      ['"openapi"','"info"','"paths"'],
    '/swagger-ui.html':   ['swagger','SwaggerUI'],
    '/crossdomain.xml':   ['cross-domain-policy','allow-access-from'],
    '/xmlrpc.php':        ['xmlrpc','XML-RPC','methodCall'],
    '/wp-login.php':      ['wp-login','WordPress','user_login'],
    '/phpmyadmin':        ['phpmyadmin','phpMyAdmin','pma'],
    '/adminer.php':       ['adminer','Adminer','db='],
    '/actuator':          ['{"_links"','actuator','self'],
    '/actuator/env':      ['activeProfiles','propertySources'],
    '/actuator/dump':     ['threadName','stackTrace','threadState'],
    '/server-status':     ['Apache Server Status','requests currently being processed'],
    '/backup.zip':        [],   # binary — reject HTML
    '/backup.tar.gz':     [],   # binary — reject HTML
    '/backup.sql':        ['INSERT INTO','CREATE TABLE','DROP TABLE'],
    '/dump.sql':          ['INSERT INTO','CREATE TABLE'],
    '/db.sql':            ['INSERT INTO','CREATE TABLE'],
    '/db_backup.zip':     [],   # binary — reject HTML
    '/.bash_history':     [],   # plain text, no HTML
    '/.ssh/id_rsa':       ['-----BEGIN'],
    '/id_rsa':            ['-----BEGIN'],
    '/server.key':        ['-----BEGIN'],
    '/private.key':       ['-----BEGIN'],
    '/shell.php':         ['<?php','shell_exec','system(','passthru'],
    '/cmd.php':           ['<?php','system(','shell_exec','exec('],
    '/c99.php':           ['<?php','c99','shell','uname'],
    '/r57.php':           ['<?php','r57','shell','passthru'],
    '/error.log':         ['PHP Fatal','PHP Warning','PHP Notice','Error'],
    '/laravel.log':       ['local.ERROR','production.ERROR','Stack trace'],
    '/debug.log':         ['ERROR','WARNING','DEBUG','TRACE'],
    '/.DS_Store':         [],   # binary
    '/crossdomain.xml':   ['cross-domain-policy','allow-access-from'],
}

# Paths that must NOT return HTML body if they are genuine files
NON_HTML_PATHS = {
    '/.env','/.env.local','/.env.production','/.env.backup',
    '/.env.staging','/.env.dev',
    '/config.json','/config.yaml','/config.ini',
    '/settings.py','/local_settings.py',
    '/.git/config','/.git/HEAD','/.git/COMMIT_EDITMSG','/.git/index',
    '/composer.json','/package.json','/requirements.txt',
    '/robots.txt','/crossdomain.xml',
    '/.htaccess','/.htpasswd',
    '/backup.sql','/dump.sql','/db.sql',
    '/backup.zip','/backup.tar.gz','/db_backup.zip',
    '/error.log','/access.log','/debug.log','/laravel.log',
    '/.bash_history','/.ssh/id_rsa','/id_rsa',
    '/server.key','/private.key',
    '/shell.php','/cmd.php','/c99.php','/r57.php',
    '/.svn/entries','/.svn/wc.db',
    '/openapi.json','/swagger.json',
}

SQL_PAYLOADS = [
    ("sq1",  "'",                                 'error'),
    ("sq2",  '"',                                 'error'),
    ("sq3",  "\\",                                'error'),
    ("sq4",  "' OR '1'='1",                       'boolean'),
    ("sq5",  "' OR 1=1--",                        'boolean'),
    ("sq6",  "' OR 1=1#",                         'boolean'),
    ("sq7",  "' AND '1'='2",                      'boolean'),
    ("sq8",  "1 OR 1=1",                          'boolean'),
    ("sq9",  "' UNION SELECT NULL--",             'union'),
    ("sq10", "' UNION SELECT NULL,NULL--",        'union'),
    ("sq11", "' UNION SELECT NULL,NULL,NULL--",   'union'),
    ("sq12", "' UNION SELECT @@version,NULL--",   'union'),
    ("sq13", "' AND SLEEP(4)--",                  'time'),
    ("sq14", "1; SELECT SLEEP(4)--",              'time'),
    ("sq15", "'; WAITFOR DELAY '0:0:4'--",        'time'),
    ("sq16", "'; SELECT pg_sleep(4)--",           'time'),
    ("sq17", "' AND BENCHMARK(5000000,MD5(1))--", 'time'),
    ("sq18", "' OR 0x31=0x31--",                  'boolean'),
    ("sq19", "admin'--",                          'auth_bypass'),
    ("sq20", "' OR ''='",                         'auth_bypass'),
    ("sq21", "1; DROP TABLE users--",             'stacked'),
    ("sq22", "' OR 1=1 LIMIT 1--",               'boolean'),
]

SQL_ERRORS = [
    'sql syntax','mysql_fetch','ora-0','pg_query','sqlite_',
    'you have an error in your sql syntax',
    'warning: mysql','supplied argument is not a valid mysql',
    'unclosed quotation mark','quoted string not properly terminated',
    'conversion failed when converting','invalid column name',
    'invalid object name','unknown column','table or view does not exist',
    '[microsoft][odbc','[mysql][','[postgresql]','mysql_num_rows',
    'unterminated string','com.mysql.jdbc','org.postgresql.jdbc',
    'java.sql.sqlexception','syntax error near','missing expression',
    'division by zero','data type mismatch','incorrect integer value',
    'odbc microsoft access','native error','db2 sql error',
    'ora-01756','ora-00933','ora-00907','pl/sql','sqlstate',
    'microsoft ole db','microsoft jet database engine',
]

XSS_PAYLOADS = [
    ('<vajra123>',                     'vajra123', 'HTML Injection'),
    ('"><vajra456>',                   'vajra456', 'Attribute Break'),
    ("'><vajra789>",                   'vajra789', 'Single Quote Break'),
    ('<script>vajraXSS</script>',      'vajraXSS', 'Script Tag'),
    ('"><img src=x onerror=vajraPOC>', 'vajraPOC', 'Event Handler XSS'),
]

TECH_PATTERNS = [
    ('WordPress',     ['wp-content','wp-includes','/wp-json/']),
    ('Drupal',        ['drupal.js','sites/default','drupalSettings']),
    ('Joomla',        ['joomla','/components/com_','mosConfig']),
    ('Magento',       ['mage/cookies','/skin/frontend/']),
    ('Shopify',       ['cdn.shopify.com','myshopify.com']),
    ('Laravel',       ['laravel_session','laravel','illuminate']),
    ('Django',        ['csrfmiddlewaretoken','django']),
    ('Ruby on Rails', ['authenticity_token','_rails']),
    ('ASP.NET',       ['__viewstate','__dopostback','aspnet_sessionid']),
    ('Spring Boot',   ['x-application-context','spring']),
    ('Express/Node',  ['x-powered-by: express','connect.sid']),
    ('Next.js',       ['__next','_next/static']),
    ('React',         ['reactroot','__reactinternals']),
    ('Angular',       ['ng-version','__ngzone']),
    ('Vue.js',        ['__vueid','vue.min','__vue__']),
    ('jQuery',        ['jquery.min.js','jquery-']),
    ('Bootstrap',     ['bootstrap.min','bootstrap.css']),
    ('Cloudflare',    ['cf-ray','__cf_bm','cf-cache-status']),
    ('Nginx',         ['server: nginx','nginx']),
    ('Apache',        ['apache','mod_']),
    ('IIS',           ['x-powered-by: asp','iis','x-aspnet']),
    ('PHP',           ['phpsessid','.php','x-powered-by: php']),
    ('Python',        ['werkzeug','gunicorn','uvicorn']),
    ('Java/Tomcat',   ['jsessionid','catalina']),
]

WAF_SIGS = {
    'Cloudflare':  ['cf-ray','__cf_bm','cloudflare','cf-cache-status'],
    'AWS WAF':     ['x-amzn-requestid','awsalb','x-amz-cf-id'],
    'Akamai':      ['akamai','x-check-cacheable','ak-bmsc'],
    'F5 BigIP':    ['bigipserver','f5','ts_'],
    'Sucuri':      ['x-sucuri-id','sucuri'],
    'ModSecurity': ['mod_security','modsec'],
    'Imperva':     ['x-iinfo','incap_ses'],
    'Barracuda':   ['barra_counter_session'],
    'Fortinet':    ['fortigate','fortiweb'],
}

SUBS = [
    'www','mail','ftp','smtp','api','dev','staging','test','beta',
    'admin','portal','login','dashboard','vpn','app','m','mobile',
    'shop','static','assets','cdn','blog','news','secure','ssl',
    'manage','old','backup','git','jenkins','wiki','docs','support',
    'webmail','remote','ns1','ns2','mx','crm','erp',
]

# ══════════════════════════════════════════════════════════════════════════════
#  SESSION HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def mk_sess(idx=0, auth_headers=None):
    s  = requests.Session()
    h  = dict(BASE_HDRS)
    ua = UA_LIST[idx % len(UA_LIST)]
    h['User-Agent'] = ua
    for key, val in SEC_CH_UA_MAP.items():
        if key in ua:
            h['Sec-Ch-Ua'] = val
            break
    h['Sec-Ch-Ua-Mobile']   = '?1' if ('iPhone' in ua or 'Android' in ua) else '?0'
    h['Sec-Ch-Ua-Platform']  = ('"iOS"'     if 'iPhone'  in ua else
                                 '"Android"' if 'Android' in ua else
                                 '"Windows"' if 'Windows' in ua else
                                 '"macOS"'   if 'Mac'     in ua else '"Linux"')
    h['Accept-Language'] = random.choice([
        'en-US,en;q=0.9','en-US,en;q=0.8',
        'en-GB,en;q=0.9,en-US;q=0.8','en-US,en;q=0.9,hi;q=0.6',
    ])
    if random.random() < 0.3:
        h['Cache-Control'] = 'no-cache'
    if auth_headers:
        h.update(auth_headers)
    s.headers.update(h)
    return s


def safe_get(url, idx=0, timeout=12, retries=4, delay=True, auth_headers=None, **kw):
    last = None
    for i in range(retries):
        try:
            se = mk_sess(idx + i, auth_headers=auth_headers)
            if delay:
                time.sleep(random.uniform(0.3, 0.8) + random.uniform(0.0, 0.3) * i)
            r = se.get(url, timeout=timeout, verify=False,
                       allow_redirects=True, **kw)
            if r.status_code in [403, 429, 503] and i < retries - 1:
                backoff = (2.0 + i * 1.2) + random.uniform(0.4, 1.2)
                print(f"     WAF {r.status_code} → retry {i+1} wait {backoff:.1f}s",
                      flush=True)
                time.sleep(backoff)
                continue
            return r
        except requests.exceptions.ConnectionError:
            time.sleep(0.8 + i * 0.4)
            last = Exception("Connection refused/reset")
        except requests.exceptions.Timeout:
            last = Exception(f"Timeout after {timeout}s")
        except Exception as e:
            last = e; time.sleep(0.5)
    raise Exception(f"All {retries} attempts failed: {last}")


def try_get_unblocked(url, idx=0, timeout=8, auth_headers=None):
    try:
        se = mk_sess(idx, auth_headers=auth_headers)
        time.sleep(random.uniform(0.1, 0.35))
        r = se.get(url, timeout=timeout, verify=False, allow_redirects=False)
        return r, False
    except Exception:
        return None, True


# ══════════════════════════════════════════════════════════════════════════════
#  RESULT SKELETON
# ══════════════════════════════════════════════════════════════════════════════
def new_R(url):
    p = urllib.parse.urlparse(url)
    return {
        'url': url, 'domain': p.netloc or url, 'scheme': p.scheme,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'status_code': None, 'final_url': url,
        'page_title': '', 'response_size': 0,
        'redirect_chain': [],
        'waf_block_size': None, 'waf_block_hash': None,
        'waf_blocked': False,
        'soft404_sizes': [], 'soft404_hashes': [],
        'soft404_available': False,
        'soft404_cluster_size': None,   # NEW: auto-detected cluster size
        'headers': {}, 'missing_headers': [],
        'info_disclosure': [], 'technologies': [], 'waf': [],
        'ssl': {}, 'cookies': [], 'forms': [], 'cors': {},
        'http_to_https': None, 'http_to_https_code': None,
        'open_ports': [], 'exposed_paths': [], 'real_exposed': 0,
        'robots': '', 'robots_paths': [], 'sitemap_urls': [],
        'mixed_content': [], 'html_comments': [],
        'inline_scripts': 0, 'external_scripts': [],
        'has_eval': False, 'has_doc_write': False, 'has_innerhtml': False,
        'param_urls': [], 'clickjacking': None,
        'open_redirect': [], 'dir_listing': [],
        'sqli': {'tested': [], 'results': [], 'vulnerable': False},
        'xss':  {'results': [], 'vulnerable': False},
        'http_methods': [], 'subdomains': [],
        'errors': [],
        'counts': {'critical':0,'high':0,'medium':0,'low':0,'info':0},
        'risk_score': 100,
        'crawled_urls':   [],
        'crawl_stats':    {'pages': 0, 'forms': 0, 'param_urls': 0},
        'nmap_results':   [],
        'nuclei_results': [],
        'zap_results':    [],
        'asset_discovery':{'apis':[], 'subdomains_full':[], 'technologies':[]},
        'findings':       [],
        'auth_used':      False,
        'confidence_summary': {'high': 0, 'medium': 0, 'low': 0},
    }


# ══════════════════════════════════════════════════════════════════════════════
#  CONFIDENCE ENGINE
# ══════════════════════════════════════════════════════════════════════════════
def confidence_level(evidence_type, confirmed=False, tool_verified=False):
    if tool_verified or confirmed:
        return 'HIGH'
    if evidence_type in ['content_signature','error_based','time_based',
                         'union_based','reflected_xss']:
        return 'HIGH'
    if evidence_type in ['server_403','401_auth','redirect_to_login',
                         'boolean_sqli','header_missing']:
        return 'MEDIUM'
    return 'LOW'


def add_finding(R, ftype, severity, title, evidence, confidence,
                owasp_key=None, path=None, param=None,
                fix=None, category='confirmed'):
    owasp, cwe, mitre = get_owasp(owasp_key or ftype)
    finding = {
        'id':         f"V{len(R['findings'])+1:03d}",
        'type':       ftype,
        'severity':   severity,
        'confidence': confidence,
        'title':      title,
        'evidence':   evidence,
        'path':       path or '',
        'param':      param or '',
        'owasp':      owasp,
        'cwe':        cwe,
        'mitre':      mitre,
        'fix':        fix or '',
        'category':   category,
        'timestamp':  datetime.now().strftime('%H:%M:%S'),
    }
    R['findings'].append(finding)
    R['confidence_summary'][confidence.lower()] = \
        R['confidence_summary'].get(confidence.lower(), 0) + 1
    return finding


# ══════════════════════════════════════════════════════════════════════════════
#  SOFT-404 FINGERPRINTING  (v5.4 — probe + cluster-auto-detect)
# ══════════════════════════════════════════════════════════════════════════════
def build_soft404_fingerprint(base, R):
    """
    Phase 1: fetch 6 nonexistent paths.
    Phase 2: cluster-auto-detect (used later after path scan collects sizes).
    Returns (sizes_set, hashes_set).
    """
    probes = [
        '/this-page-does-not-exist-vajra-12345',
        '/nonexistent-vajra-path-99999.php',
        '/fake-vajra-config-xyzabc.json',
        '/definitely-missing-vajra-dir-abc/index.html',
        '/vajra-no-such-file-abcdef1234.txt',
        '/zzz-vajra-probe-nonexistent-xyz.html',
    ]
    sizes  = set()
    hashes = set()
    ok_count = 0

    for probe in probes:
        try:
            time.sleep(random.uniform(0.25, 0.55))
            pr = mk_sess(random.randint(0, len(UA_LIST)-1)).get(
                f"{base}{probe}", timeout=6,
                verify=False, allow_redirects=True)
            if pr.status_code == 200 and len(pr.content) > 50:
                sizes.add(len(pr.content))
                hashes.add(hashlib.md5(pr.content).hexdigest())
                ok_count += 1
        except: pass

    R['soft404_sizes']     = list(sizes)
    R['soft404_hashes']    = list(hashes)
    R['soft404_available'] = ok_count >= 2

    print(f"     soft-404 fp: {ok_count}/6 probes ok | "
          f"sizes={sizes} | hashes={[h[:8] for h in hashes]}", flush=True)
    return sizes, hashes


def detect_soft404_cluster(path_scan_results):
    """
    FIX #1 — Post-scan cluster detection.
    After all paths are probed, look at the sizes of all 200-OK responses.
    If >= CLUSTER_FRACTION of them are within CLUSTER_BAND bytes of the mode,
    that mode is the catch-all / soft-404 size.
    Returns the cluster_size (int) or None.
    """
    sizes = [r['size'] for r in path_scan_results if r.get('status') == 200]
    if len(sizes) < 5:
        return None

    # Round each size to nearest 100 to find the modal bucket
    bucketed = [round(s / 100) * 100 for s in sizes]
    counter  = Counter(bucketed)
    mode_bucket, mode_count = counter.most_common(1)[0]

    if mode_count / len(sizes) >= CLUSTER_FRACTION:
        # Confirm: all sizes within ±CLUSTER_BAND of mode_bucket * 100
        cluster_center = mode_bucket  # already in bytes (bucket*100 ≈ center)
        print(f"     [CLUSTER DETECT] mode_bucket={mode_bucket*100}B "
              f"count={mode_count}/{len(sizes)} "
              f"({mode_count/len(sizes)*100:.0f}%) → SOFT-404 DETECTED",
              flush=True)
        return mode_bucket * 100
    return None


def is_soft_404(content_bytes, soft404_sizes, soft404_hashes,
                cluster_size=None):
    """
    Returns True if this response matches the catch-all page.
    Checks: hash match → size match (probe) → cluster match.
    """
    h    = hashlib.md5(content_bytes).hexdigest()
    clen = len(content_bytes)

    if h in soft404_hashes:
        return True
    for s in soft404_sizes:
        if abs(clen - s) <= 120:
            return True
    # FIX #1: cluster-based check
    if cluster_size is not None and abs(clen - cluster_size) <= CLUSTER_BAND:
        return True
    return False


def content_is_real(path, content_bytes):
    """
    Returns True / False / None.
    True  = content signature matched (definitely real).
    False = wrong content type or missing required signature (fake / soft-404).
    None  = no opinion.
    """
    key = path.split('?')[0].rstrip('/')
    try:
        text     = content_bytes[:8000].decode('utf-8', errors='ignore')
        text_low = text.lower()
    except:
        return True   # binary → accept

    is_html = ('<html' in text_low or '<!doctype' in text_low or
               '<head' in text_low or '<body' in text_low)

    # Rule A: path must NOT return HTML
    if key in NON_HTML_PATHS and is_html:
        return False

    # Rule B: content signature
    required = PATH_CONTENT_CHECKS.get(key)
    if required is None:
        return None
    if not required:
        # Empty list = binary / plain-text file; HTML body means fake
        if is_html:
            return False
        return True   # any non-HTML content accepted

    for req in required:
        if req.lower() in text_low:
            return True
    return False


def verdict_real(path, content_bytes,
                 soft404_sizes, soft404_hashes, soft404_available,
                 cluster_size=None):
    """
    Master real/fake decision.
    Returns (is_real: bool, reason: str)
    """
    # 1. Soft-404 match (probe + cluster) → always fake
    if is_soft_404(content_bytes, soft404_sizes, soft404_hashes, cluster_size):
        return False, 'soft-404 match (probe or cluster)'

    # 2. Content signature check
    cv = content_is_real(path, content_bytes)
    if cv is True:
        return True,  'content signature matched'
    if cv is False:
        return False, 'wrong content type (HTML where non-HTML expected)'

    # 3. No definitive content check — use heuristics
    try:
        text_low = content_bytes[:1000].decode('utf-8', errors='ignore').lower()
    except:
        return True, 'binary — accepted'

    is_html = '<html' in text_low or '<!doctype' in text_low

    # Large HTML for non-web paths → unverified
    if is_html and len(content_bytes) > 8000 and path not in [
        '/admin','/admin/','/admin/login','/wp-login.php',
        '/phpmyadmin','/console','/swagger-ui.html',
    ]:
        return True, 'unverified — large HTML (verify manually)'

    if soft404_available:
        return True, 'accepted — size differs from soft-404 baseline'
    return True, 'accepted (no soft-404 baseline)'


# ══════════════════════════════════════════════════════════════════════════════
#  WEBSITE CRAWLER  (v5.4 — Cloudflare bypass headers)
# ══════════════════════════════════════════════════════════════════════════════
def do_crawl(url, R, auth_headers=None):
    p           = urllib.parse.urlparse(url)
    base_domain = p.netloc
    base_url    = f"{p.scheme}://{p.netloc}"
    visited     = set()
    queue       = deque([(url, 0)])
    crawled     = []
    all_forms   = []
    param_urls  = set()
    apis_found  = set()

    # Cloudflare-friendly headers for crawler
    cf_extra = {
        'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Referer':         'https://www.google.com/',
        'Sec-Fetch-Dest':  'document',
        'Sec-Fetch-Mode':  'navigate',
        'Sec-Fetch-Site':  'cross-site',
        'Sec-Fetch-User':  '?1',
    }
    if auth_headers:
        cf_extra.update(auth_headers)

    # Respect robots.txt
    rp = RobotFileParser()
    try:
        rp.set_url(f"{base_url}/robots.txt")
        rp.read()
    except:
        rp = None

    print(f"     Crawler starting BFS max={MAX_CRAWL_PAGES} depth={MAX_CRAWL_DEPTH}",
          flush=True)

    while queue and len(visited) < MAX_CRAWL_PAGES:
        cur_url, depth = queue.popleft()
        if depth > MAX_CRAWL_DEPTH:
            continue
        norm = cur_url.split('#')[0].rstrip('/')
        if norm in visited:
            continue
        visited.add(norm)

        if rp:
            try:
                if not rp.can_fetch('*', cur_url):
                    continue
            except: pass

        try:
            time.sleep(random.uniform(0.4, 0.9))
            sess = mk_sess(random.randint(0, len(UA_LIST)-1))
            sess.headers.update(cf_extra)
            resp = sess.get(cur_url, timeout=10, verify=False,
                            allow_redirects=True)

            if resp.status_code in [403, 429, 503]:
                # Try once more with a different UA after a short wait
                time.sleep(random.uniform(1.5, 3.0))
                sess2 = mk_sess(random.randint(0, len(UA_LIST)-1))
                sess2.headers.update(cf_extra)
                resp = sess2.get(cur_url, timeout=10, verify=False,
                                 allow_redirects=True)
                if resp.status_code in [403, 429, 503]:
                    continue

            if resp.status_code != 200:
                continue
            ct = resp.headers.get('content-type','')
            if 'html' not in ct.lower():
                continue

            crawled.append({
                'url':   cur_url,
                'status': resp.status_code,
                'size':   len(resp.content),
                'title':  '',
                'depth':  depth,
            })

            soup = BeautifulSoup(resp.text, 'html.parser')
            t    = soup.find('title')
            crawled[-1]['title'] = t.get_text().strip()[:80] if t else ''

            for form in soup.find_all('form'):
                has_csrf = bool(form.find('input', {
                    'name': re.compile(r'csrf|token|_token|nonce|verify', re.I)}))
                all_forms.append({
                    'page':     cur_url,
                    'action':   urllib.parse.urljoin(
                                    cur_url, form.get('action','') or cur_url),
                    'method':   form.get('method','GET').upper(),
                    'inputs':   [f"{i.get('type','text')}:{i.get('name','?')}"
                                 for i in form.find_all('input')][:8],
                    'has_csrf': has_csrf,
                })

            for a in soup.find_all('a', href=True):
                href = a['href'].strip()
                if not href or href.startswith(('javascript:','mailto:','tel:')):
                    continue
                full = urllib.parse.urljoin(cur_url, href).split('#')[0]
                pu   = urllib.parse.urlparse(full)
                if CRAWL_SAME_DOMAIN_ONLY and pu.netloc != base_domain:
                    continue
                if not full.startswith(('http://','https://')):
                    continue
                if '=' in full:
                    param_urls.add(full)
                if re.search(r'/api/|/v\d+/|/graphql|/rest/', full, re.I):
                    apis_found.add(full[:120])
                norm2 = full.rstrip('/')
                if norm2 not in visited:
                    queue.append((full, depth + 1))

        except Exception:
            pass

    R['crawled_urls']  = crawled
    R['param_urls']    = list(param_urls)[:30]
    R['forms']         = all_forms[:20]
    R['crawl_stats']   = {
        'pages':      len(crawled),
        'forms':      len(all_forms),
        'param_urls': len(param_urls),
    }
    R['asset_discovery']['apis'] = list(apis_found)[:20]
    print(f"     Crawled {len(crawled)} pages | "
          f"forms={len(all_forms)} | params={len(param_urls)} | "
          f"apis={len(apis_found)}", flush=True)


# ══════════════════════════════════════════════════════════════════════════════
#  STAGE 1 — HTTP + Headers
# ══════════════════════════════════════════════════════════════════════════════
def do_http(url, R, auth_headers=None):
    try:
        resp = safe_get(url, idx=0, timeout=15, retries=4,
                        auth_headers=auth_headers)
        R['status_code']    = resp.status_code
        R['final_url']      = resp.url
        R['headers']        = dict(resp.headers)
        R['response_size']  = len(resp.content)
        R['redirect_chain'] = [r.url for r in resp.history]

        if resp.status_code in [403, 429]:
            R['waf_blocked']    = True
            R['waf_block_size'] = len(resp.content)
            R['waf_block_hash'] = hashlib.md5(resp.content).hexdigest()

        lch     = {k.lower(): v.lower() for k, v in resp.headers.items()}
        lch_raw = {k.lower(): v         for k, v in resp.headers.items()}

        R['missing_headers'] = [h for h in SEC_HEADERS if h not in lch]

        for h in R['missing_headers']:
            sev  = ('HIGH'   if h in ['content-security-policy',
                                       'strict-transport-security'] else 'MEDIUM')
            okey = ('missing_csp'  if 'csp' in h else
                    'missing_hsts' if 'strict' in h else 'info_disclosure')
            add_finding(R, okey, sev,
                        f"Missing Security Header: {h}",
                        f"Header '{h}' absent from HTTP response",
                        confidence_level('header_missing'),
                        owasp_key=okey, category='confirmed',
                        fix=f"Add response header: {h}")

        for h in ['server','x-powered-by','x-aspnet-version','x-generator',
                  'via','x-backend','x-varnish','x-runtime','x-debug-token']:
            if lch_raw.get(h):
                R['info_disclosure'].append({'header':h,'value':lch_raw[h]})
                add_finding(R, 'info_disclosure', 'LOW',
                            f"Server Information Disclosure: {h}",
                            f"{h}: {lch_raw[h]}",
                            'HIGH', owasp_key='info_disclosure',
                            category='confirmed',
                            fix=f"Remove or sanitize the '{h}' response header")

        acao = lch_raw.get('access-control-allow-origin','Not set')
        R['cors'] = {
            'value':       acao,
            'wildcard':    acao.strip() == '*',
            'credentials': lch_raw.get('access-control-allow-credentials','Not set'),
            'methods':     lch_raw.get('access-control-allow-methods','Not set'),
        }
        if R['cors']['wildcard']:
            add_finding(R, 'cors_wildcard', 'HIGH',
                        'CORS Wildcard Origin Policy',
                        'Access-Control-Allow-Origin: *',
                        'HIGH', owasp_key='cors_wildcard', category='confirmed',
                        fix='Restrict CORS to specific trusted origins')

        R['clickjacking'] = (
            not lch.get('x-frame-options','') and
            'frame-ancestors' not in lch.get('content-security-policy','')
        )
        if R['clickjacking']:
            add_finding(R, 'clickjacking', 'MEDIUM',
                        'Clickjacking Protection Missing',
                        'No X-Frame-Options or CSP frame-ancestors directive',
                        'HIGH', owasp_key='clickjacking', category='confirmed',
                        fix='Add: X-Frame-Options: DENY  or  CSP: frame-ancestors none')

        for ck in resp.cookies:
            rest  = {k.lower(): v for k, v in ck._rest.items()}
            flags = {
                'name':     ck.name, 'secure':   ck.secure,
                'httponly': 'httponly' in rest,
                'samesite': rest.get('samesite','Not Set'),
                'domain':   ck.domain or R['domain'],
            }
            R['cookies'].append(flags)
            if not ck.secure:
                add_finding(R, 'cookie_no_secure', 'MEDIUM',
                            f"Cookie Missing Secure Flag: {ck.name}",
                            f"Cookie '{ck.name}' sent without Secure flag",
                            'HIGH', owasp_key='cookie_no_secure',
                            category='confirmed',
                            fix=f"Set-Cookie: {ck.name}=...; Secure; HttpOnly; SameSite=Strict")
            if 'httponly' not in rest:
                add_finding(R, 'cookie_no_http', 'MEDIUM',
                            f"Cookie Missing HttpOnly Flag: {ck.name}",
                            f"Cookie '{ck.name}' accessible via JavaScript",
                            'HIGH', owasp_key='cookie_no_http',
                            category='confirmed',
                            fix=f"Add HttpOnly flag to cookie '{ck.name}'")

        body_low = resp.text.lower()
        hdr_str  = ' '.join(v.lower() for v in resp.headers.values())
        combined = body_low + ' ' + hdr_str

        tech = set()
        for name, kws in TECH_PATTERNS:
            if any(kw.lower() in combined for kw in kws):
                tech.add(name)
        R['technologies'] = sorted(tech)

        waf = []
        for wname, inds in WAF_SIGS.items():
            if any(i in combined for i in inds):
                waf.append(wname)
        R['waf'] = waf or ['None detected']

        if R['scheme'] == 'https':
            try:
                hr = mk_sess(1).get(
                    url.replace('https://','http://',1),
                    timeout=5, allow_redirects=False, verify=False)
                R['http_to_https_code'] = hr.status_code
                R['http_to_https']      = (hr.status_code in [301,302,308]
                                            if hr.status_code not in [403,429,503]
                                            else None)
            except:
                R['http_to_https'] = None

        if resp.status_code == 200 and len(resp.content) > 200:
            soup = BeautifulSoup(resp.text, 'html.parser')
            t    = soup.find('title')
            R['page_title'] = t.get_text().strip()[:100] if t else ''

            domain = R['domain']
            links  = set()
            for a in soup.find_all('a', href=True):
                full = urllib.parse.urljoin(url, a['href'])
                pu   = urllib.parse.urlparse(full)
                if '=' in full and (pu.netloc == domain or not pu.netloc):
                    links.add(full)
            if not R['param_urls']:
                R['param_urls'] = list(links)[:15]

            rp_names = ['next','redirect','url','return','returnto','goto',
                        'target','redir','redirect_uri','continue','dest']
            for a in soup.find_all('a', href=True):
                full = urllib.parse.urljoin(url, a['href'])
                qs   = urllib.parse.parse_qs(urllib.parse.urlparse(full).query)
                for rp in rp_names:
                    if rp in qs:
                        R['open_redirect'].append({'param':rp,'url':full[:100]})
            R['open_redirect'] = R['open_redirect'][:5]
            if R['open_redirect']:
                add_finding(R, 'open_redirect', 'MEDIUM',
                            'Potential Open Redirect Parameters Found',
                            f"Redirect params: {[x['param'] for x in R['open_redirect']]}",
                            'MEDIUM', owasp_key='open_redirect',
                            category='potential',
                            fix='Validate and whitelist redirect destinations')

            if not R['forms']:
                for form in soup.find_all('form'):
                    has_csrf = bool(form.find('input',{
                        'name': re.compile(r'csrf|token|_token|nonce|verify', re.I)}))
                    R['forms'].append({
                        'page':      url,
                        'action':    form.get('action','(current)'),
                        'method':    form.get('method','GET').upper(),
                        'inputs':    [f"{i.get('type','text')}:{i.get('name','?')}"
                                      for i in form.find_all('input')][:8],
                        'has_csrf':  has_csrf,
                        'multipart': form.get('enctype','') == 'multipart/form-data',
                    })

            for form in R['forms']:
                if not form.get('has_csrf') and form.get('method') == 'POST':
                    add_finding(R, 'csrf_missing', 'MEDIUM',
                                'Missing CSRF Token on POST Form',
                                f"Form action: {str(form.get('action',''))[:60]}",
                                'MEDIUM', owasp_key='csrf_missing',
                                category='potential',
                                fix='Add CSRF token to all state-changing forms')

            for tag in soup.find_all(['script','link','img','source']):
                src = tag.get('src', tag.get('href',''))
                if src and src.startswith('http://') and R['scheme'] == 'https':
                    R['mixed_content'].append(src[:100])
            R['mixed_content'] = R['mixed_content'][:6]
            if R['mixed_content']:
                add_finding(R, 'mixed_content', 'MEDIUM',
                            'Mixed Content (HTTP resources on HTTPS page)',
                            f"Found {len(R['mixed_content'])} HTTP resource(s)",
                            'HIGH', owasp_key='mixed_content',
                            category='confirmed',
                            fix='Replace all HTTP resource URLs with HTTPS')

            R['html_comments'] = [
                c.strip()[:150]
                for c in soup.find_all(string=lambda t: isinstance(t, Comment))
                if c.strip() and len(c.strip()) > 5
            ][:6]

            inlines = soup.find_all('script', src=False)
            all_js  = ' '.join(s.string or '' for s in inlines)
            R['inline_scripts']   = len(inlines)
            R['has_eval']         = 'eval(' in all_js
            R['has_doc_write']    = 'document.write' in all_js
            R['has_innerhtml']    = 'innerhtml' in all_js.lower()
            R['external_scripts'] = [t['src'] for t in soup.find_all('script', src=True)][:8]
        else:
            R['page_title'] = (
                f'[{resp.status_code} — '
                f'{"WAF/Cloudflare blocking scan" if resp.status_code==403 else "blocked"}]'
            )

    except Exception as e:
        R['errors'].append(f"HTTP: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  STAGE 2 — SSL
# ══════════════════════════════════════════════════════════════════════════════
def do_ssl(R):
    domain = R['domain']
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert  = s.getpeercert()
            ciph  = s.cipher()
            proto = s.version()
            na    = cert.get('notAfter','')
            try:
                days = (datetime.strptime(na,'%b %d %H:%M:%S %Y %Z') -
                        datetime.utcnow()).days
            except:
                days = -1
            weak_p = proto in ['TLSv1','TLSv1.1','SSLv2','SSLv3']
            weak_c = any(w in (ciph[0] if ciph else '')
                         for w in ['RC4','DES','EXPORT','NULL','ANON','MD5'])
            risk = ('CRITICAL' if days < 7  else
                    'HIGH'     if days < 30  else
                    'MEDIUM'   if days < 60  else
                    'HIGH'     if weak_p or weak_c else 'LOW')
            R['ssl'] = {
                'valid': True,
                'subject': dict(x[0] for x in cert.get('subject',[])),
                'issuer':  dict(x[0] for x in cert.get('issuer',[])),
                'expires': na, 'days_left': days,
                'protocol': proto,
                'cipher': ciph[0] if ciph else '',
                'cipher_bits': ciph[2] if ciph else 0,
                'san': [x[1] for x in cert.get('subjectAltName',[])][:8],
                'risk': risk, 'weak_proto': weak_p, 'weak_cipher': weak_c,
            }
            if weak_p:
                add_finding(R, 'ssl_weak', 'HIGH',
                            f'Weak TLS Protocol: {proto}',
                            f'Server supports deprecated {proto}',
                            'HIGH', owasp_key='ssl_weak', category='confirmed',
                            fix=f'Disable {proto}; enable TLS 1.2/1.3 only')
            if days < 30:
                add_finding(R, 'ssl_expired',
                            'CRITICAL' if days <= 0 else 'HIGH',
                            f'SSL Certificate Expiring Soon: {days} days',
                            f'Certificate expires: {na}',
                            'HIGH', owasp_key='ssl_expired', category='confirmed',
                            fix='Renew SSL certificate immediately')
    except ssl.SSLCertVerificationError as e:
        R['ssl'] = {'valid':False,'risk':'CRITICAL','error':f'Cert INVALID: {e}'}
        add_finding(R, 'ssl_expired', 'CRITICAL', 'Invalid SSL Certificate',
                    str(e)[:120], 'HIGH', owasp_key='ssl_expired',
                    category='confirmed',
                    fix='Install a valid SSL certificate from a trusted CA')
    except Exception as e:
        R['ssl'] = {'valid':False,'risk':'MEDIUM','error':str(e)[:200]}


# ══════════════════════════════════════════════════════════════════════════════
#  STAGE 3a — Socket Port Scan
# ══════════════════════════════════════════════════════════════════════════════
def do_ports(R):
    for port, (svc, risk, desc) in PORTS.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.8)
            if s.connect_ex((R['domain'], port)) == 0:
                R['open_ports'].append({
                    'port': port, 'service': svc, 'risk': risk, 'description': desc,
                })
                if port not in EXPECTED_PORTS and risk in ['CRITICAL','HIGH']:
                    add_finding(R, 'open_port_db', risk,
                                f'Dangerous Open Port: {port}/{svc}',
                                desc, 'HIGH', owasp_key='open_port_db',
                                path=f":{port}", category='confirmed',
                                fix=f'Firewall port {port} from public internet')
            s.close()
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  STAGE 3b — Nmap
# ══════════════════════════════════════════════════════════════════════════════
def do_nmap(R):
    if not NMAP_PATH:
        return
    domain = R['domain']
    try:
        ports_str = ','.join(str(p) for p in PORTS.keys())
        cmd = [
            NMAP_PATH, '-sV', '--version-intensity', '5',
            '-p', ports_str,
            '--script', 'banner,http-title,ssl-cert',
            '--open', '-T3', '--host-timeout', '60s',
            '-oX', '-', domain
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0 and result.stdout:
            R['nmap_results'] = parse_nmap_xml(result.stdout)
            print(f"     Nmap: {len(R['nmap_results'])} port findings", flush=True)
            for nr in R['nmap_results']:
                if nr.get('state') == 'open':
                    add_finding(R, 'open_port_db', nr.get('risk','MEDIUM'),
                                f"[Nmap] Open Port: {nr['port']}/{nr.get('service','')} "
                                f"{nr.get('version','')}",
                                nr.get('script_output','')[:200],
                                'HIGH', owasp_key='open_port_db',
                                path=f":{nr['port']}", category='confirmed')
        else:
            print(f"     Nmap: no output", flush=True)
    except FileNotFoundError:
        print(f"     Nmap: not found — skipping", flush=True)
    except subprocess.TimeoutExpired:
        print(f"     Nmap: timed out", flush=True)
    except Exception as e:
        print(f"     Nmap error: {e}", flush=True)
        R['errors'].append(f"Nmap: {e}")


def parse_nmap_xml(xml_str):
    results = []
    try:
        from xml.etree import ElementTree as ET
        root = ET.fromstring(xml_str)
        for host in root.findall('host'):
            for port_el in host.findall('.//port'):
                state_el   = port_el.find('state')
                service_el = port_el.find('service')
                if state_el is None:
                    continue
                port_num = int(port_el.get('portid', 0))
                state    = state_el.get('state','')
                svc_name = service_el.get('name','') if service_el is not None else ''
                svc_ver  = ((service_el.get('product','') + ' ' +
                              service_el.get('version',''))
                             if service_el is not None else '').strip()
                scripts  = []
                for sc in port_el.findall('script'):
                    scripts.append(f"{sc.get('id','')}: {sc.get('output','')[:100]}")
                risk_info = PORTS.get(port_num, (svc_name,'MEDIUM',''))[1]
                results.append({
                    'port': port_num, 'state': state,
                    'service': svc_name, 'version': svc_ver,
                    'script_output': ' | '.join(scripts)[:300],
                    'risk': risk_info,
                })
    except Exception:
        pass
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  STAGE 3c — Nuclei
# ══════════════════════════════════════════════════════════════════════════════
def do_nuclei(url, R):
    if not NUCLEI_PATH:
        return
    try:
        cmd = [
            NUCLEI_PATH, '-u', url,
            '-severity', 'critical,high,medium',
            '-silent', '-json',
            '-timeout', '10',
            '-rate-limit', '20',
            '-bulk-size', '5',
            '-no-color',
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if result.stdout:
            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    R['nuclei_results'].append(entry)
                    sev = entry.get('info',{}).get('severity','medium').upper()
                    add_finding(R, 'nuclei', sev,
                                f"[Nuclei] {entry.get('info',{}).get('name','Finding')}",
                                (entry.get('matched-at','') + ' — ' +
                                 entry.get('info',{}).get('description','')[:120]),
                                'HIGH', path=entry.get('matched-at',''),
                                category='confirmed',
                                fix=entry.get('info',{}).get('remediation',''))
                except json.JSONDecodeError:
                    pass
            print(f"     Nuclei: {len(R['nuclei_results'])} findings", flush=True)
        else:
            print(f"     Nuclei: no findings or not available", flush=True)
    except FileNotFoundError:
        print(f"     Nuclei: not found — skipping", flush=True)
    except subprocess.TimeoutExpired:
        print(f"     Nuclei: timed out", flush=True)
    except Exception as e:
        print(f"     Nuclei error: {e}", flush=True)
        R['errors'].append(f"Nuclei: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  STAGE 3d — OWASP ZAP
# ══════════════════════════════════════════════════════════════════════════════
def do_zap(url, R):
    if not ZAP_API_URL:
        return
    try:
        base = ZAP_API_URL.rstrip('/')
        key  = f"&apikey={ZAP_API_KEY}" if ZAP_API_KEY else ""

        resp     = requests.get(
            f"{base}/JSON/spider/action/scan/?url={urllib.parse.quote(url)}{key}",
            timeout=10)
        scan_id  = resp.json().get('scan','')
        for _ in range(30):
            time.sleep(3)
            prog = requests.get(
                f"{base}/JSON/spider/view/status/?scanId={scan_id}{key}",
                timeout=5).json()
            if int(prog.get('status',0)) >= 100:
                break

        resp2    = requests.get(
            f"{base}/JSON/ascan/action/scan/?url={urllib.parse.quote(url)}{key}",
            timeout=10)
        ascan_id = resp2.json().get('scan','')
        for _ in range(60):
            time.sleep(5)
            prog = requests.get(
                f"{base}/JSON/ascan/view/status/?scanId={ascan_id}{key}",
                timeout=5).json()
            if int(prog.get('status',0)) >= 100:
                break

        alerts = requests.get(
            f"{base}/JSON/alert/view/alerts/?baseurl="
            f"{urllib.parse.quote(url)}&start=0&count=50{key}",
            timeout=10).json().get('alerts',[])
        R['zap_results'] = alerts[:40]
        sev_map = {'High':'HIGH','Medium':'MEDIUM','Low':'LOW','Informational':'LOW'}
        for alert in alerts[:20]:
            sev = sev_map.get(alert.get('risk','Low'),'LOW')
            add_finding(R, 'zap', sev,
                        f"[ZAP] {alert.get('name','Alert')}",
                        alert.get('description','')[:200],
                        'HIGH', path=alert.get('url','')[:100],
                        param=alert.get('param',''),
                        category='confirmed',
                        fix=alert.get('solution','')[:200])
        print(f"     ZAP: {len(alerts)} alerts", flush=True)
    except Exception as e:
        print(f"     ZAP: not available — {e}", flush=True)


# ══════════════════════════════════════════════════════════════════════════════
#  STAGE 4 — Path Discovery  (v5.4 — cluster-based soft-404)
# ══════════════════════════════════════════════════════════════════════════════
def do_paths(url, R, auth_headers=None):
    p    = urllib.parse.urlparse(url)
    base = f"{p.scheme}://{p.netloc}"

    # WAF block fingerprint
    block_sizes  = set()
    block_hashes = set()
    if R.get('waf_block_size'):
        block_sizes.add(R['waf_block_size'])
    if R.get('waf_block_hash'):
        block_hashes.add(R['waf_block_hash'])

    for probe in ['/vajra-waf-probe-abc123',
                  '/vajra-waf-probe-xyz999',
                  '/vajra-waf-probe-def456']:
        try:
            time.sleep(random.uniform(0.3, 0.7))
            pr = mk_sess(random.randint(0, len(UA_LIST)-1)).get(
                f"{base}{probe}", timeout=5,
                verify=False, allow_redirects=False)
            if pr.status_code in [403, 429]:
                block_sizes.add(len(pr.content))
                block_hashes.add(hashlib.md5(pr.content).hexdigest())
        except: pass

    print(f"     WAF fp:    sizes={block_sizes} "
          f"hashes={[h[:8] for h in block_hashes]}", flush=True)

    soft404_sizes, soft404_hashes = build_soft404_fingerprint(base, R)
    soft404_available = R['soft404_available']

    def is_waf_block(code, content):
        if code not in [403, 429]:
            return False
        h    = hashlib.md5(content).hexdigest()
        clen = len(content)
        if h in block_hashes:
            return True
        for bs in block_sizes:
            if abs(clen - bs) <= 30:
                return True
        return False

    for dpath in ['/uploads/','/images/','/files/','/assets/','/backup/']:
        try:
            time.sleep(random.uniform(0.2, 0.5))
            r = mk_sess(random.randint(0, len(UA_LIST)-1)).get(
                f"{base}{dpath}", timeout=4,
                verify=False, allow_redirects=False)
            if (r.status_code == 200 and
                not is_soft_404(r.content, soft404_sizes, soft404_hashes) and
                ('index of' in r.text.lower() or
                 'parent directory' in r.text.lower())):
                R['dir_listing'].append(dpath)
                add_finding(R, 'dir_listing', 'CRITICAL',
                            f'Directory Listing Enabled: {dpath}',
                            f'Server returns directory index for {dpath}',
                            'HIGH', owasp_key='dir_listing',
                            path=dpath, category='confirmed',
                            fix=f'Add "Options -Indexes" (Apache) or "autoindex off" (Nginx)')
        except: pass

    # ── Phase 1: collect raw probe results ───────────────────────────────
    raw_results = []   # store all probed entries for cluster analysis
    for i, (path, cat_sev, desc) in enumerate(PATHS):
        try:
            base_delay = random.uniform(0.12, 0.38)
            if i > 0 and i % 15 == 0:
                base_delay += random.uniform(0.6, 1.3)
            time.sleep(base_delay)

            r, failed = try_get_unblocked(
                f"{base}{path}",
                idx=random.randint(0, len(UA_LIST)-1),
                auth_headers=auth_headers)

            if failed or r is None:
                continue

            raw_results.append({
                'path':     path,
                'status':   r.status_code,
                'size':     len(r.content),
                'content':  r.content,
                'headers':  dict(r.headers),
                'severity': cat_sev,
                'desc':     desc,
            })
        except: pass

    # ── FIX #1: cluster-based soft-404 auto-detection ────────────────────
    cluster_size = detect_soft404_cluster(raw_results)
    R['soft404_cluster_size'] = cluster_size
    if cluster_size is not None:
        # Backfill soft404 data so is_soft_404() works
        print(f"     [CLUSTER] Soft-404 size detected: ~{cluster_size}B — "
              f"filtering false positives", flush=True)

    # ── Phase 2: verdict each result now that cluster_size is known ───────
    real = 0
    for entry in raw_results:
        try:
            path    = entry['path']
            code    = entry['status']
            body    = entry['content']
            size    = entry['size']
            desc    = entry['desc']
            cat_sev = entry['severity']

            if is_waf_block(code, body):
                continue

            if code == 200 and size > 50:
                is_real, reason = verdict_real(
                    path, body,
                    soft404_sizes, soft404_hashes, soft404_available,
                    cluster_size=cluster_size)

                if is_real:
                    conf_ev = ('content_signature'
                               if reason == 'content signature matched'
                               else 'unverified')
                    conf    = confidence_level(
                        conf_ev,
                        confirmed=(reason == 'content signature matched'))
                    note    = f'ACCESSIBLE ✓ {size:,}B — {desc}'
                    if 'verify manually' in reason:
                        note += ' ⚠ VERIFY'
                        conf  = 'MEDIUM'

                    R['exposed_paths'].append({
                        'path': path, 'status': code, 'size': size,
                        'severity': cat_sev, 'note': note,
                        'reason': reason, 'real': True,
                        'confidence': conf,
                    })

                    okey = ('exposed_git'    if '.git'   in path else
                            'exposed_env'    if '.env'   in path else
                            'exposed_backup' if any(x in path for x in
                                ['backup','dump','.sql','.zip','.tar']) else
                            'exposed_admin'  if any(x in path for x in
                                ['admin','phpmyadmin','pma','dbadmin']) else
                            'exposed_config')
                    add_finding(R, okey, cat_sev,
                                f'Exposed Sensitive Path: {path}',
                                note, conf, owasp_key=okey,
                                path=path, category='confirmed',
                                fix=f'Block access to {path} via server config or firewall')
                    real += 1

            elif code == 403 and not is_waf_block(code, body):
                R['exposed_paths'].append({
                    'path': path, 'status': code, 'size': size,
                    'severity': 'MEDIUM',
                    'note': f'Server-403 (path confirmed) — {desc}',
                    'reason': 'server-level 403', 'real': False,
                    'confidence': 'MEDIUM',
                })
            elif code == 401:
                R['exposed_paths'].append({
                    'path': path, 'status': code, 'size': size,
                    'severity': 'MEDIUM',
                    'note': f'Auth required (path confirmed) — {desc}',
                    'reason': '401 auth challenge', 'real': False,
                    'confidence': 'MEDIUM',
                })
            elif code in [301, 302, 308]:
                loc = entry['headers'].get('location','')[:50]
                R['exposed_paths'].append({
                    'path': path, 'status': code, 'size': size,
                    'severity': 'LOW',
                    'note': f'Redirect → {loc} — {desc}',
                    'reason': 'redirect', 'real': False,
                    'confidence': 'LOW',
                })
        except: pass

    R['real_exposed'] = real

    for ep, key in [('/robots.txt','robots'),('/sitemap.xml','sitemap')]:
        try:
            time.sleep(random.uniform(0.2, 0.5))
            r = mk_sess(0).get(f"{base}{ep}", timeout=6, verify=False)
            if (r.status_code == 200 and
                not is_waf_block(r.status_code, r.content) and
                not is_soft_404(r.content, soft404_sizes, soft404_hashes,
                                cluster_size)):
                if key == 'robots':
                    R['robots']       = r.text[:600]
                    R['robots_paths'] = re.findall(
                        r'(?:Disallow|Allow):\s*(.+)', r.text)[:20]
                else:
                    R['sitemap_urls'] = re.findall(
                        r'<loc>(.*?)</loc>', r.text)[:15]
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  STAGE 5a — SQL Injection
# ══════════════════════════════════════════════════════════════════════════════
def do_sqli(url, R, auth_headers=None):
    results, tested, seen = [], [], set()
    p     = urllib.parse.urlparse(url)
    cands = []
    if '=' in url: cands.append(url)
    for u in R.get('param_urls',[]):
        if '=' in u and urllib.parse.urlparse(u).netloc == p.netloc:
            cands.append(u)
    base = f"{p.scheme}://{p.netloc}"
    for s in ['?id=1','?page=1','?q=test','?search=a','?cat=1',
              '?item=1','?news=1','?pid=1','?user=admin','?name=test']:
        cands.append(base + s)

    for test_url in cands[:6]:
        pp     = urllib.parse.urlparse(test_url)
        params = urllib.parse.parse_qs(pp.query, keep_blank_values=True)
        if not params: continue
        for param in list(params.keys())[:3]:
            pk = f"{param}@{pp.netloc}{pp.path}"
            if pk in seen: continue
            seen.add(pk); tested.append(pk)
            try:
                br   = mk_sess(0, auth_headers=auth_headers).get(
                    test_url, timeout=8, verify=False)
                blen = len(br.text)
                blow = br.text.lower()
            except: continue
            for pname, payload, ptype in SQL_PAYLOADS:
                try:
                    tp = dict(params); tp[param] = [payload]
                    nu = urllib.parse.urlunparse(pp._replace(
                        query=urllib.parse.urlencode(tp, doseq=True)))
                    t0  = time.time()
                    rr  = mk_sess(1, auth_headers=auth_headers).get(
                        nu, timeout=12, verify=False, allow_redirects=False)
                    ela = time.time() - t0
                    bl  = rr.text.lower()
                    errs    = [e for e in SQL_ERRORS if e in bl and e not in blow]
                    time_b  = ptype == 'time' and ela > 3.5
                    bool_b  = (ptype in ['boolean','auth_bypass'] and
                               abs(len(rr.text)-blen) > 500 and
                               rr.status_code == br.status_code)
                    union_b = (ptype == 'union' and 'null' in bl and
                               'null' not in blow and rr.status_code == 200)
                    if errs or time_b or bool_b or union_b:
                        vt   = ('Error-Based SQLi'       if errs    else
                                'Time-Based Blind SQLi'   if time_b  else
                                'Union-Based SQLi'        if union_b else
                                'Boolean/Auth-Bypass SQLi')
                        ev   = (f"DB errors: {errs[:2]}"             if errs   else
                                f"Delay {ela:.2f}s"                   if time_b else
                                f"Body delta {abs(len(rr.text)-blen):,}B")
                        conf = confidence_level(
                            'error_based' if errs else
                            'time_based'  if time_b else
                            'union_based' if union_b else 'boolean_sqli')
                        results.append({
                            'url': nu[:120], 'param': param,
                            'payload': payload, 'type': vt,
                            'evidence': ev, 'severity': 'CRITICAL',
                            'confidence': conf,
                        })
                        add_finding(R, 'sqli', 'CRITICAL',
                                    f'SQL Injection — {vt}',
                                    f"Param: {param} | {ev}",
                                    conf, owasp_key='sqli',
                                    path=nu[:80], param=param,
                                    category='confirmed',
                                    fix='Use parameterized queries / prepared statements')
                        break
                except: pass
    R['sqli'] = {'tested': tested, 'results': results,
                 'vulnerable': bool(results)}


# ══════════════════════════════════════════════════════════════════════════════
#  STAGE 5b — XSS
# ══════════════════════════════════════════════════════════════════════════════
def do_xss(url, R, auth_headers=None):
    results = []
    p     = urllib.parse.urlparse(url)
    cands = [url] + R.get('param_urls',[])[:5]
    cands = [u for u in cands
             if '=' in u and urllib.parse.urlparse(u).netloc == p.netloc]
    if not cands:
        base  = f"{p.scheme}://{p.netloc}"
        cands = [f"{base}?q=test", f"{base}?search=test",
                 f"{base}?s=test",  f"{base}?name=test"]
    for test_url in cands[:4]:
        pp     = urllib.parse.urlparse(test_url)
        params = urllib.parse.parse_qs(pp.query, keep_blank_values=True)
        if not params: continue
        for param in list(params.keys())[:2]:
            for payload, indicator, xtype in XSS_PAYLOADS:
                try:
                    tp = dict(params); tp[param] = [payload]
                    nu = urllib.parse.urlunparse(pp._replace(
                        query=urllib.parse.urlencode(tp, doseq=True)))
                    rr = mk_sess(0, auth_headers=auth_headers).get(
                        nu, timeout=8, verify=False)
                    if indicator in rr.text:
                        conf = confidence_level('reflected_xss', confirmed=True)
                        results.append({
                            'url': nu[:120], 'param': param,
                            'payload': payload,
                            'type': f'Reflected {xtype}',
                            'severity': 'HIGH',
                            'evidence': f'"{indicator}" reflected unencoded',
                            'confidence': conf,
                        })
                        add_finding(R, 'xss', 'HIGH',
                                    f'Reflected XSS — {xtype}',
                                    f"Param: {param} | indicator '{indicator}' reflected",
                                    conf, owasp_key='xss',
                                    path=nu[:80], param=param,
                                    category='confirmed',
                                    fix='Encode all user output. Implement strict CSP.')
                        break
                except: pass
    R['xss'] = {'results': results, 'vulnerable': bool(results)}


# ══════════════════════════════════════════════════════════════════════════════
#  STAGE 5c — HTTP Methods
# ══════════════════════════════════════════════════════════════════════════════
def do_methods(url, R):
    p    = urllib.parse.urlparse(url)
    base = f"{p.scheme}://{p.netloc}"
    rm   = {
        'TRACE':   ('HIGH',     'Cross-Site Tracing — steals HttpOnly cookies'),
        'PUT':     ('CRITICAL', 'File upload — enables RCE'),
        'DELETE':  ('HIGH',     'Arbitrary file deletion'),
        'PATCH':   ('MEDIUM',   'Content modification without auth'),
        'CONNECT': ('MEDIUM',   'Proxy tunneling'),
    }
    for method, (risk, desc) in rm.items():
        try:
            rr = requests.request(method, base, timeout=5,
                                  verify=False, headers=BASE_HDRS)
            if rr.status_code not in [405,501,400,403,404]:
                R['http_methods'].append({
                    'method': method, 'status': rr.status_code,
                    'severity': risk, 'risk': desc,
                })
                okey = 'http_put' if method == 'PUT' else 'http_trace'
                add_finding(R, okey, risk,
                            f'Dangerous HTTP Method Allowed: {method}',
                            f'Server responded HTTP {rr.status_code} to {method}',
                            'HIGH', owasp_key=okey, category='confirmed',
                            fix=f'Disable {method} in server config')
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  STAGE 5d — Subdomains + Asset Discovery
# ══════════════════════════════════════════════════════════════════════════════
def do_subs(R):
    base  = re.sub(r'^www\.', '', R['domain'])
    found = []
    for sub in SUBS[:25]:
        fqdn = f"{sub}.{base}"
        if fqdn == R['domain']: continue
        try:
            socket.setdefaulttimeout(1.2)
            ip = socket.gethostbyname(fqdn)
            found.append({'subdomain': fqdn, 'ip': ip})
        except: pass

    R['subdomains'] = [x['subdomain'] for x in found]
    R['asset_discovery']['subdomains_full'] = found

    for entry in found[:8]:
        try:
            r = mk_sess(0).get(f"https://{entry['subdomain']}",
                               timeout=5, verify=False, allow_redirects=True)
            combined = r.text.lower() + ' '.join(
                v.lower() for v in r.headers.values())
            tech = set()
            for name, kws in TECH_PATTERNS:
                if any(kw.lower() in combined for kw in kws):
                    tech.add(name)
            entry['technologies'] = sorted(tech)
        except:
            entry['technologies'] = []

    R['asset_discovery']['technologies'] = sorted(R['technologies'])


# ══════════════════════════════════════════════════════════════════════════════
#  AUTH HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def build_auth_headers(auth_config):
    if not auth_config:
        return None
    t = auth_config.get('type','')
    if t == 'bearer':
        return {'Authorization': f"Bearer {auth_config.get('token','')}"}
    if t == 'basic':
        cred = base64.b64encode(
            f"{auth_config.get('username','')}:{auth_config.get('password','')}".encode()
        ).decode()
        return {'Authorization': f"Basic {cred}"}
    if t == 'cookie':
        return {'Cookie': auth_config.get('cookie','')}
    if t == 'header':
        return {auth_config.get('header_name','X-Token'):
                auth_config.get('header_value','')}
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  COUNTS + SCORE  (v5.4 — FIX #4: accurate scoring)
# ══════════════════════════════════════════════════════════════════════════════
def compute_counts(R):
    c = R['counts']

    sr = R['ssl'].get('risk','LOW')
    if   sr == 'CRITICAL': c['critical'] += 1
    elif sr == 'HIGH':     c['high']     += 1
    elif sr == 'MEDIUM':   c['medium']   += 1
    else:                  c['low']      += 1

    for h in R['missing_headers']:
        if h in ['content-security-policy','strict-transport-security']:
            c['high']   += 1
        elif h in ['x-frame-options','x-content-type-options','permissions-policy']:
            c['medium'] += 1
        else:
            c['low']    += 1

    # Only count REAL (200-OK confirmed) paths toward score
    for ep in R['exposed_paths']:
        if ep.get('real') and ep['status'] == 200:
            s = ep['severity']
            if   s == 'CRITICAL': c['critical'] += 1
            elif s == 'HIGH':     c['high']     += 1
            elif s == 'MEDIUM':   c['medium']   += 1
            else:                 c['low']      += 1
        else:
            c['info'] += 1

    for op in R['open_ports']:
        if op['port'] in EXPECTED_PORTS:
            c['info'] += 1
            continue
        s = op['risk']
        if   s == 'CRITICAL': c['critical'] += 1
        elif s == 'HIGH':     c['high']     += 1
        elif s == 'MEDIUM':   c['medium']   += 1
        else:                 c['low']      += 1

    for _ in R['sqli'].get('results',[]): c['critical'] += 1
    for _ in R['xss'].get('results',[]):  c['high']     += 1

    for m in R['http_methods']:
        s = m['severity']
        if   s == 'CRITICAL': c['critical'] += 1
        elif s == 'HIGH':     c['high']     += 1
        else:                 c['medium']   += 1

    for ck in R['cookies']:
        if not ck['secure'] or not ck['httponly']: c['medium'] += 1
        else:                                       c['low']    += 1

    if R['cors'].get('wildcard'): c['high']    += 1
    if R['clickjacking']:         c['medium']  += 1
    c['medium']   += len(R['mixed_content'])
    c['critical']  += len(R['dir_listing'])
    c['low']       += len(R['info_disclosure'])
    c['medium']    += len(R['open_redirect'])

    for nr in R.get('nuclei_results',[]):
        sv = nr.get('info',{}).get('severity','medium').lower()
        if sv == 'critical': c['critical'] += 1
        elif sv == 'high':   c['high']     += 1
        elif sv == 'medium': c['medium']   += 1
        else:                c['low']      += 1

    for za in R.get('zap_results',[]):
        sv = za.get('risk','Low').lower()
        if sv == 'high':   c['high']   += 1
        elif sv == 'medium': c['medium'] += 1
        else:              c['low']    += 1

    score  = 100
    score -= c['critical'] * 20
    score -= c['high']     * 7
    score -= c['medium']   * 4
    score -= c['low']      * 1

    floor = 30 if R.get('waf_blocked') else 5
    R['risk_score'] = max(floor, min(100, score))
    return c


# ══════════════════════════════════════════════════════════════════════════════
#  DEDUPLICATION
# ══════════════════════════════════════════════════════════════════════════════
def dedup_findings(R):
    seen   = {}
    unique = []
    order  = {'CRITICAL':4,'HIGH':3,'MEDIUM':2,'LOW':1}
    for f in R['findings']:
        key = f"{f['type']}:{f['path']}:{f['param']}"
        if key not in seen:
            seen[key] = len(unique)
            unique.append(f)
        else:
            idx = seen[key]
            if order.get(f['severity'],0) > order.get(unique[idx]['severity'],0):
                unique[idx] = f
    R['findings'] = unique
    print(f"     Dedup: {len(R['findings'])} unique findings", flush=True)


# ══════════════════════════════════════════════════════════════════════════════
#  JOB RUNNER
# ══════════════════════════════════════════════════════════════════════════════
def upd(sid, n, name):
    with jobs_lock:
        if sid in scan_jobs:
            scan_jobs[sid]['stage']      = n
            scan_jobs[sid]['stage_name'] = name
    print(f"[{n}/9] {name}", flush=True)


def run_job(sid, url, auth_config=None):
    with jobs_lock:
        scan_jobs[sid]['status'] = 'scanning'
    R = new_R(url)

    auth_headers  = build_auth_headers(auth_config)
    R['auth_used'] = bool(auth_headers)

    try:
        upd(sid, 1, 'HTTP Fetch + Header Analysis')
        do_http(url, R, auth_headers=auth_headers)
        print(f"     status={R['status_code']} waf={R['waf_blocked']} "
              f"size={R['response_size']:,}B "
              f"missing_hdrs={len(R['missing_headers'])}", flush=True)

        upd(sid, 2, 'Website Crawling + Asset Discovery')
        do_crawl(url, R, auth_headers=auth_headers)
        do_subs(R)
        print(f"     subs={len(R['subdomains'])} "
              f"apis={len(R['asset_discovery']['apis'])}", flush=True)

        upd(sid, 3, 'SSL/TLS Deep Inspection')
        do_ssl(R)
        print(f"     {R['ssl'].get('days_left','?')}d/"
              f"{R['ssl'].get('protocol','?')}/"
              f"{R['ssl'].get('risk','?')}", flush=True)

        upd(sid, 4, 'Port Scan — Socket + Nmap')
        do_ports(R)
        do_nmap(R)
        print(f"     open={[p['port'] for p in R['open_ports']]} "
              f"nmap={len(R['nmap_results'])}", flush=True)

        upd(sid, 5, 'Path Discovery — soft-404 + cluster filter')
        do_paths(url, R, auth_headers=auth_headers)
        print(f"     total={len(R['exposed_paths'])} "
              f"real_200={R['real_exposed']} "
              f"soft404_avail={R['soft404_available']} "
              f"cluster_size={R['soft404_cluster_size']} "
              f"dir={R['dir_listing']}", flush=True)

        upd(sid, 6, 'SQLi + XSS + Methods + ZAP + Nuclei')
        do_sqli(url, R, auth_headers=auth_headers)
        do_xss(url, R, auth_headers=auth_headers)
        do_methods(url, R)
        do_nuclei(url, R)
        do_zap(url, R)
        print(f"     sqli={R['sqli']['vulnerable']} "
              f"xss={R['xss']['vulnerable']} "
              f"methods={len(R['http_methods'])} "
              f"nuclei={len(R['nuclei_results'])} "
              f"zap={len(R['zap_results'])}", flush=True)

        upd(sid, 7, 'AI Report — GPU LLM + Deduplication')
        dedup_findings(R)
        compute_counts(R)
        print(f"     SCORE={R['risk_score']} "
              f"C={R['counts']['critical']} H={R['counts']['high']} "
              f"M={R['counts']['medium']} L={R['counts']['low']} "
              f"I={R['counts']['info']} "
              f"findings={len(R['findings'])}", flush=True)
        stext  = fmt_llm(R)
        prompt = build_prompt(stext, url, R)
        print(f"     prompt ~{len(prompt)//4} tokens", flush=True)
        report = query_llm(prompt)
        print(f"     report ~{len(report)//4} tokens", flush=True)

        upd(sid, 8, 'Building HTML + TXT Document')
        full_doc      = build_doc(report, R)
        full_html_doc = build_html_report(report, R)

        upd(sid, 9, 'Finalizing')
        stats = {
            'critical': R['counts']['critical'],
            'high':     R['counts']['high'],
            'medium':   R['counts']['medium'],
            'low':      R['counts']['low'],
            'score':    R['risk_score'],
        }
        with jobs_lock:
            doc_store[sid]           = full_doc
            doc_store[sid + '_html'] = full_html_doc
            scan_jobs[sid].update({
                'status':             'done',
                'report':             report,
                'stats':              stats,
                'sqli_vuln':          R['sqli']['vulnerable'],
                'xss_vuln':           R['xss']['vulnerable'],
                'waf_blocked':        R['waf_blocked'],
                'risk_score':         R['risk_score'],
                'soft404_available':  R['soft404_available'],
                'cluster_size':       R['soft404_cluster_size'],
                'findings_count':     len(R['findings']),
                'crawl_stats':        R['crawl_stats'],
                'auth_used':          R['auth_used'],
                'confidence_summary': R['confidence_summary'],
            })
        if len(doc_store) > 50:
            del doc_store[next(iter(doc_store))]

    except Exception as e:
        import traceback; traceback.print_exc()
        with jobs_lock:
            scan_jobs[sid].update({'status':'error','error':str(e)})


# ══════════════════════════════════════════════════════════════════════════════
#  LLM HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def fmt_llm(R):
    L = []; A = L.append; c = R['counts']
    A(f"TARGET: {R['url']}")
    A(f"STATUS: HTTP {R['status_code']} | {R['response_size']:,}B | "
      f"WAF_BLOCKED:{R['waf_blocked']} | AUTH:{R['auth_used']}")
    A(f"TITLE: {R['page_title']}")
    A(f"TECH: {', '.join(R['technologies']) or 'Not detected'}")
    A(f"WAF_CDN: {', '.join(R['waf'])}")
    A(f"CRAWL: pages={R['crawl_stats']['pages']} "
      f"forms={R['crawl_stats']['forms']} "
      f"param_urls={R['crawl_stats']['param_urls']}")
    A(f"ASSET_DISCOVERY: subs={len(R['subdomains'])} "
      f"apis={len(R['asset_discovery']['apis'])}")
    A(f"SOFT404_FP: probe_available={R['soft404_available']} "
      f"cluster_size={R['soft404_cluster_size']} "
      f"sizes={R['soft404_sizes']}")
    A(f"SCORE: {R['risk_score']}/100 | "
      f"C:{c['critical']} H:{c['high']} M:{c['medium']} "
      f"L:{c['low']} I:{c['info']}")
    A(f"CONFIDENCE: HIGH:{R['confidence_summary'].get('high',0)} "
      f"MEDIUM:{R['confidence_summary'].get('medium',0)} "
      f"LOW:{R['confidence_summary'].get('low',0)}")

    A(f"\n=UNIFIED_FINDINGS ({len(R['findings'])})=")
    confirmed  = [f for f in R['findings'] if f['category']=='confirmed']
    potential  = [f for f in R['findings'] if f['category']=='potential']
    info_finds = [f for f in R['findings'] if f['category']=='informational']

    A(f"\n-- CONFIRMED ({len(confirmed)}) --")
    for f in confirmed[:25]:
        A(f"  [{f['severity']}][{f['confidence']} CONF] {f['id']} {f['title']}")
        A(f"    Evidence: {f['evidence'][:80]}")
        A(f"    OWASP:{f['owasp']} | {f['cwe']} | MITRE:{f['mitre']}")
        if f.get('fix'):
            A(f"    Fix: {f['fix'][:80]}")

    A(f"\n-- POTENTIAL ({len(potential)}) --")
    for f in potential[:15]:
        A(f"  [{f['severity']}][{f['confidence']} CONF] {f['id']} {f['title']}")
        A(f"    Evidence: {f['evidence'][:80]}")
        A(f"    OWASP:{f['owasp']} | {f['cwe']}")

    A(f"\n-- INFORMATIONAL ({len(info_finds)}) --")
    for f in info_finds[:10]:
        A(f"  [INFO] {f['title']}")

    A(f"\n=MISSING_HEADERS ({len(R['missing_headers'])}/10)=")
    for h in R['missing_headers']: A(f"  MISSING: {h}")

    ssl = R['ssl']
    A(f"\n=SSL=")
    if ssl.get('valid'):
        A(f"  VALID | {ssl.get('protocol')} | "
          f"{ssl.get('cipher')} {ssl.get('cipher_bits')}bit")
        A(f"  Expires:{ssl.get('expires')} "
          f"({ssl.get('days_left')}d) [{ssl.get('risk')}]")
        A(f"  weak_proto:{ssl.get('weak_proto')} "
          f"weak_cipher:{ssl.get('weak_cipher')}")
    else:
        A(f"  INVALID [{ssl.get('risk')}]: {ssl.get('error')}")

    A(f"\n=OPEN_PORTS ({len(R['open_ports'])})=")
    for p in R['open_ports']:
        exp = ' [EXPECTED]' if p['port'] in EXPECTED_PORTS else ''
        A(f"  {p['port']}/{p['service']} [{p['risk']}]{exp}")

    real_p  = [x for x in R['exposed_paths'] if x.get('real')]
    other_p = [x for x in R['exposed_paths'] if not x.get('real')]
    A(f"\n=REAL_ACCESSIBLE_PATHS ({len(real_p)})=")
    for ep in real_p:
        A(f"  [{ep['severity']}][{ep.get('confidence','?')}] {ep['path']} "
          f"{ep['note'][:60]}")

    A(f"\n=SERVER_CONFIRMED_PATHS ({len(other_p)} non-200)=")
    for ep in other_p[:8]:
        A(f"  [{ep['severity']}] {ep['path']} HTTP:{ep['status']}")

    A(f"\n=SQLI= vulnerable:{R['sqli']['vulnerable']}")
    for r in R['sqli']['results']:
        A(f"  [CRITICAL][{r.get('confidence','?')}] {r['type']} "
          f"param={r['param']} evidence={r['evidence']}")

    A(f"\n=XSS= vulnerable:{R['xss']['vulnerable']}")
    for r in R['xss']['results']:
        A(f"  [HIGH][{r.get('confidence','?')}] {r['type']} param={r['param']}")

    if R['nuclei_results']:
        A(f"\n=NUCLEI ({len(R['nuclei_results'])})=")
        for n in R['nuclei_results'][:10]:
            A(f"  [{n.get('info',{}).get('severity','?').upper()}] "
              f"{n.get('info',{}).get('name','?')} → "
              f"{n.get('matched-at','')[:60]}")

    if R['zap_results']:
        A(f"\n=ZAP ({len(R['zap_results'])})=")
        for z in R['zap_results'][:10]:
            A(f"  [{z.get('risk','?')}] {z.get('name','?')[:60]}")

    if R['subdomains']:
        A(f"\n=SUBDOMAINS= {', '.join(R['subdomains'][:10])}")
    if R['asset_discovery']['apis']:
        A(f"\n=APIS= {', '.join(R['asset_discovery']['apis'][:8])}")
    if R['robots_paths']:
        A(f"\n=ROBOTS_DISALLOWED= {', '.join(R['robots_paths'][:8])}")
    if R['dir_listing']:
        A(f"\n=DIR_LISTING= {R['dir_listing']}")

    if R.get('soft404_cluster_size'):
        A(f"\n=SOFT404_CLUSTER= Cluster-based soft-404 detected at "
          f"~{R['soft404_cluster_size']}B. "
          f"All paths returning HTML within ±{CLUSTER_BAND}B of this size "
          f"were filtered as false positives.")
    elif not R['soft404_available']:
        A(f"\n=SOFT404_WARNING= Soft-404 fingerprint unavailable. "
          f"Path results use content-signature validation only.")
    if R['errors']:
        A(f"\n=ERRORS= {'; '.join(R['errors'][:3])}")

    return '\n'.join(L)[:7000]


def build_prompt(scan_text, url, R):
    c    = R['counts']
    date = datetime.now().strftime('%Y-%m-%d')
    conf = R.get('confidence_summary',{})
    return (
        f"You are a senior penetration tester (OSCP/OSWE). "
        f"Write a complete professional security assessment report.\n\n"
        f"SCAN_START\n{scan_text}\nSCAN_END\n\n"
        f"Rules:\n"
        f"1. Three sections: CONFIRMED VULNERABILITIES, POTENTIAL ISSUES, "
        f"INFORMATIONAL FINDINGS.\n"
        f"2. Each finding: Severity, Confidence (High/Medium/Low), CVSS, "
        f"OWASP, CWE, MITRE ATT&CK TTP, Evidence, Impact, Fix with exact "
        f"nginx/apache/IIS commands.\n"
        f"3. Skip duplicate findings. No generic padding.\n"
        f"4. Do NOT repeat the report twice. Write it ONCE.\n\n"
        f"{'='*70}\n"
        f"VAJRANET SECURITY ASSESSMENT REPORT v5.4\n"
        f"{'='*70}\n"
        f"Target          : {url}\n"
        f"Date            : {date}\n"
        f"Risk Score      : {R['risk_score']}/100\n"
        f"Authenticated   : {'Yes' if R['auth_used'] else 'No'}\n"
        f"CRITICAL:{c['critical']}  HIGH:{c['high']}  "
        f"MEDIUM:{c['medium']}  LOW:{c['low']}\n"
        f"Confidence      : HIGH:{conf.get('high',0)} "
        f"MEDIUM:{conf.get('medium',0)} LOW:{conf.get('low',0)}\n"
        f"Crawled Pages   : {R['crawl_stats']['pages']}\n"
        f"WAF/CDN         : {', '.join(R['waf'])}\n"
        f"Soft-404 Cluster: {R['soft404_cluster_size'] or 'Not detected'}\n"
        f"{'='*70}\n\n"
        f"EXECUTIVE SUMMARY\n"
        f"-----------------\n"
    )


def query_llm(prompt):
    payload = {
        "prompt": prompt, "n_predict": 4096,
        "temperature": 0.15, "top_k": 20, "top_p": 0.85,
        "repeat_penalty": 1.08,
        "stop": ["SCAN_START","SCAN_END","<|user|>","<|im_start|>",
                 "[INST]","Human:","User:"],
        "n_threads": THREADS, "n_gpu_layers": GPU_LAYERS,
    }
    for attempt in range(3):
        try:
            t0  = time.time()
            r   = requests.post(
                      f"http://127.0.0.1:{LLAMA_PORT}/completion",
                      json=payload, timeout=360)
            r.raise_for_status()
            out = r.json().get("content","").strip()
            if not out: raise ValueError("Empty response")
            ela = time.time() - t0
            tok = max(1, len(out)//4)
            print(f"     {ela:.1f}s ~{tok}tok {tok/ela:.1f}t/s", flush=True)
            return out
        except Exception as e:
            print(f"[LLM ERR] {attempt+1}/3: {e}", flush=True)
            if attempt == 2:
                return (f"LLM unavailable: {e}\n\n"
                        f"Raw scan data is in the JSON section below.\n"
                        f"Check llama-server is running on port {LLAMA_PORT}.")
            time.sleep(3)


def build_doc(report, R):
    """FIX #8 — write report exactly ONCE."""
    c    = R['counts']
    sep  = '=' * 72
    conf = R.get('confidence_summary',{})
    findings_index = '\n'.join(
        f"  {f['id']} [{f['severity']}][{f['confidence']}] "
        f"{f['title']} | {f['owasp']} | {f['cwe']}"
        for f in R['findings']
    )
    raw_data = json.dumps(R, indent=2, default=str)[:14000]
    return (
        f"{sep}\n  VAJRANET AI SECURITY ASSESSMENT REPORT v5.4\n{sep}\n"
        f"  Target         : {R['url']}\n"
        f"  Generated      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"  Authenticated  : {'Yes' if R['auth_used'] else 'No'}\n"
        f"  Page Title     : {R.get('page_title','')}\n"
        f"  Technologies   : {', '.join(R.get('technologies',[]))}\n"
        f"  WAF/CDN        : {', '.join(R.get('waf',[]))}\n"
        f"  Crawled Pages  : {R['crawl_stats']['pages']}\n"
        f"  Risk Score     : {R['risk_score']}/100\n"
        f"  CRITICAL:{c['critical']}  HIGH:{c['high']}  "
        f"MEDIUM:{c['medium']}  LOW:{c['low']}  INFO:{c['info']}\n"
        f"  Confidence     : HIGH:{conf.get('high',0)} "
        f"MEDIUM:{conf.get('medium',0)} LOW:{conf.get('low',0)}\n"
        f"  Total Findings : {len(R['findings'])}\n"
        f"  Real Exposed   : {R['real_exposed']} HTTP-200 paths\n"
        f"  Soft-404 Cluster: {R['soft404_cluster_size'] or 'Not detected'}\n"
        f"  Subdomains     : {', '.join(R['subdomains'][:10])}\n"
        f"{sep}\n\n"
        f"{report}\n\n"
        f"{sep}\n  FINDINGS INDEX\n{sep}\n\n"
        f"{findings_index}\n\n"
        f"{sep}\n  RAW SCAN DATA\n{sep}\n\n"
        f"{raw_data}\n"
    )


def build_html_report(report, R):
    c    = R['counts']
    conf = R.get('confidence_summary',{})
    date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def sev_color(s):
        return {'CRITICAL':'#ff2020','HIGH':'#ff7700',
                'MEDIUM':'#ffd000','LOW':'#00cc30','INFO':'#00aaff'}.get(s,'#aaa')

    def conf_badge(c_):
        col = {'HIGH':'#00cc30','MEDIUM':'#ffd000','LOW':'#ff7700'}.get(c_,'#aaa')
        return (f'<span style="color:{col};border:1px solid {col};'
                f'padding:1px 5px;border-radius:3px;font-size:10px">{c_}</span>')

    findings_html = ''
    for f in R['findings']:
        col = sev_color(f['severity'])
        fix_html = (f'<div style="font-size:11px;color:#ccc;margin-top:4px">'
                    f'<b style="color:#00aaff">Fix:</b> {f["fix"][:150]}</div>'
                    if f.get('fix') else '')
        findings_html += (
            f'<div style="border:1px solid {col};border-radius:4px;'
            f'margin:8px 0;padding:12px;background:rgba(0,0,0,.3)">'
            f'<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">'
            f'<span style="color:{col};font-weight:bold;font-size:13px">[{f["severity"]}]</span>'
            f'{conf_badge(f["confidence"])}'
            f'<span style="color:#00ffc8;font-weight:bold">{f["id"]}</span>'
            f'<span style="color:#ddd">{f["title"]}</span></div>'
            f'<div style="font-size:11px;color:#aaa;margin-bottom:4px">'
            f'{f["owasp"]} &nbsp;|&nbsp; {f["cwe"]} &nbsp;|&nbsp; MITRE:{f["mitre"]}</div>'
            f'<div style="font-size:11px;color:#ccc">'
            f'<b style="color:#bbaa00">Evidence:</b> {f["evidence"][:150]}</div>'
            f'{fix_html}</div>'
        )

    report_html = report.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
    report_html = re.sub(r'\[CRITICAL\]',
        '<span style="color:#ff2020;font-weight:bold">[CRITICAL]</span>',report_html)
    report_html = re.sub(r'\[HIGH\]',
        '<span style="color:#ff7700;font-weight:bold">[HIGH]</span>',report_html)
    report_html = re.sub(r'\[MEDIUM\]',
        '<span style="color:#ffd000">[MEDIUM]</span>',report_html)
    report_html = re.sub(r'\[LOW\]',
        '<span style="color:#00cc30">[LOW]</span>',report_html)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>VajraNet Security Report — {R['url']}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:#020402;color:#bfbfbf;font-family:'Courier New',monospace;padding:30px;}}
h1{{color:#00ff41;font-size:22px;letter-spacing:4px;margin-bottom:5px;}}
h2{{color:#00cc30;font-size:14px;letter-spacing:2px;margin:20px 0 10px;
    border-bottom:1px solid #1a3a1a;padding-bottom:6px;}}
.header-box{{border:1px solid #1a3a1a;border-radius:4px;padding:16px;margin-bottom:20px;}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:16px 0;}}
.stat{{text-align:center;padding:12px;border-radius:4px;}}
.report-body{{white-space:pre-wrap;font-size:12px;line-height:1.8;}}
</style>
</head>
<body>
<h1>⚡ VAJRANET SECURITY ASSESSMENT REPORT v5.4</h1>
<div class="header-box">
  <div><b style="color:#00cc30">Target:</b> {R['url']}</div>
  <div><b style="color:#00cc30">Generated:</b> {date}</div>
  <div><b style="color:#00cc30">Authenticated:</b> {'Yes' if R['auth_used'] else 'No'}</div>
  <div><b style="color:#00cc30">Crawled Pages:</b> {R['crawl_stats']['pages']}</div>
  <div><b style="color:#00cc30">Soft-404 Cluster:</b> {R['soft404_cluster_size'] or 'Not detected'}</div>
  <div><b style="color:#00cc30">Risk Score:</b>
    <span style="color:#00ffc8;font-size:18px;font-weight:bold">{R['risk_score']}/100</span>
  </div>
</div>
<div class="stats">
  <div class="stat" style="border:1px solid #ff2020">
    <div style="color:#ff2020;font-size:28px;font-weight:bold">{c['critical']}</div>
    <div style="font-size:10px;color:#662020;letter-spacing:2px">CRITICAL</div>
  </div>
  <div class="stat" style="border:1px solid #ff7700">
    <div style="color:#ff7700;font-size:28px;font-weight:bold">{c['high']}</div>
    <div style="font-size:10px;color:#663300;letter-spacing:2px">HIGH</div>
  </div>
  <div class="stat" style="border:1px solid #ffd000">
    <div style="color:#ffd000;font-size:28px;font-weight:bold">{c['medium']}</div>
    <div style="font-size:10px;color:#665500;letter-spacing:2px">MEDIUM</div>
  </div>
  <div class="stat" style="border:1px solid #00ffc8">
    <div style="color:#00ffc8;font-size:28px;font-weight:bold">{R['risk_score']}</div>
    <div style="font-size:10px;color:#005544;letter-spacing:2px">RISK SCORE</div>
  </div>
</div>
<div><b style="color:#00cc30">Confidence:</b>
  <span style="color:#00cc30">HIGH:{conf.get('high',0)}</span> &nbsp;
  <span style="color:#ffd000">MEDIUM:{conf.get('medium',0)}</span> &nbsp;
  <span style="color:#ff7700">LOW:{conf.get('low',0)}</span>
</div>
<h2>FINDINGS ({len(R['findings'])} total)</h2>
{findings_html}
<h2>AI ANALYSIS REPORT</h2>
<div class="report-body">{report_html}</div>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════════
#  FRONTEND
# ══════════════════════════════════════════════════════════════════════════════
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>VajraNet v5.4 — AI Scanner</title>
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box;}
:root{
  --g:#00ff41;--gd:#00cc30;--bg:#020402;--bd:#0e1e0e;
  --red:#ff2020;--ora:#ff7700;--yel:#ffd000;
  --blu:#00aaff;--cyn:#00ffc8;--wht:#bfbfbf;--dim:#303030;
  --fn:'Courier New',monospace;
}
html,body{height:100%;overflow:hidden;}
body{background:var(--bg);color:var(--g);font-family:var(--fn);
  display:flex;flex-direction:column;position:relative;}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
  background-image:linear-gradient(rgba(0,255,65,.025) 1px,transparent 1px),
    linear-gradient(90deg,rgba(0,255,65,.025) 1px,transparent 1px);
  background-size:48px 48px;animation:gridDrift 60s linear infinite;}
@keyframes gridDrift{from{background-position:0 0;}to{background-position:48px 48px;}}
body::after{content:'';position:fixed;inset:0;pointer-events:none;z-index:9999;
  background:repeating-linear-gradient(0deg,transparent 0,transparent 3px,
  rgba(0,0,0,.08) 3px,rgba(0,0,0,.08) 4px);}
.top,.body,.btm{position:relative;z-index:1;}
.top{display:flex;align-items:center;gap:10px;flex-shrink:0;padding:9px 20px;
  border-bottom:1px solid var(--bd);
  background:linear-gradient(90deg,rgba(2,6,2,.98),rgba(6,12,6,.95),rgba(2,6,2,.98));
  box-shadow:0 2px 20px rgba(0,0,0,.8);flex-wrap:wrap;}
.logo{font-size:20px;font-weight:bold;letter-spacing:5px;color:var(--g);
  text-shadow:0 0 15px var(--g),0 0 30px var(--gd);}
.logo em{color:#fff;font-style:normal;}
.pill{font-size:8px;letter-spacing:1.5px;border:1px solid #162016;
  padding:3px 9px;border-radius:2px;color:#1a2a1a;background:rgba(0,10,0,.6);
  transition:all .3s;white-space:nowrap;}
.pill.on{color:var(--gd);border-color:var(--gd);box-shadow:0 0 8px rgba(0,200,50,.2);}
.pill.warn{color:var(--yel);border-color:#665500;}
.pill.err{color:var(--red);border-color:#660000;box-shadow:0 0 8px rgba(255,0,0,.2);}
.pill.pulse{animation:pillPulse 2s ease-in-out infinite;}
@keyframes pillPulse{0%,100%{box-shadow:0 0 8px rgba(0,200,50,.2);}
  50%{box-shadow:0 0 16px rgba(0,255,65,.5),0 0 30px rgba(0,255,65,.2);}}
.top-r{margin-left:auto;font-size:8px;color:#1a2a1a;letter-spacing:1px;}
.body{display:flex;flex:1;overflow:hidden;}
.L{width:320px;flex-shrink:0;display:flex;flex-direction:column;overflow-y:auto;
  background:linear-gradient(180deg,rgba(4,8,4,.97),rgba(6,10,6,.95));
  border-right:1px solid var(--bd);}
.R{flex:1;display:flex;flex-direction:column;overflow:hidden;}
.ph{display:flex;align-items:center;gap:7px;padding:8px 15px;
  font-size:8px;letter-spacing:2px;color:#253525;
  background:linear-gradient(90deg,rgba(4,10,4,.98),rgba(8,14,8,.95));
  border-bottom:1px solid var(--bd);}
.ph .d{width:6px;height:6px;border-radius:50%;background:var(--gd);
  box-shadow:0 0 6px var(--gd);flex-shrink:0;}
.pb{padding:13px 15px;}
.url-in,.auth-in{width:100%;padding:8px 10px;background:rgba(0,8,0,.8);
  border:1px solid #1a3a1a;border-radius:3px;color:var(--g);
  font-family:var(--fn);font-size:11px;outline:none;transition:all .3s;
  margin-bottom:7px;}
.url-in:focus,.auth-in:focus{border-color:var(--g);
  box-shadow:0 0 12px rgba(0,255,65,.15);}
.url-in::placeholder,.auth-in::placeholder{color:#182018;}
.sel{width:100%;padding:7px 8px;background:rgba(0,8,0,.9);
  border:1px solid #1a3a1a;border-radius:3px;color:var(--gd);
  font-family:var(--fn);font-size:10px;margin-bottom:7px;outline:none;}
.lbl{font-size:8px;color:#2a4a2a;letter-spacing:1px;margin-bottom:3px;}
.auth-box{border:1px solid #0e2a0e;border-radius:3px;padding:8px;
  margin-bottom:8px;background:rgba(0,5,0,.5);}
.auth-toggle{font-size:9px;color:#1e3e1e;cursor:pointer;
  border:1px solid #0e2a0e;background:none;padding:4px 8px;
  border-radius:2px;width:100%;text-align:left;transition:color .2s;}
.auth-toggle:hover{color:var(--gd);}
.auth-fields{display:none;margin-top:8px;}
.auth-fields.open{display:block;}
.btn{width:100%;padding:12px;background:transparent;border:1px solid var(--g);
  color:var(--g);font-family:var(--fn);font-size:11px;font-weight:bold;
  letter-spacing:3px;border-radius:3px;cursor:pointer;position:relative;
  overflow:hidden;transition:all .3s;}
.btn:hover:not(:disabled){
  background:linear-gradient(135deg,rgba(0,255,65,.15),rgba(0,200,50,.1));
  box-shadow:0 0 25px rgba(0,255,65,.3);}
.btn:disabled{opacity:.25;cursor:not-allowed;}
.hint{font-size:8px;color:#182018;line-height:1.9;margin-top:8px;}
.hint b{color:#243224;}
.sg{display:flex;align-items:flex-start;gap:8px;padding:7px 8px;
  border-radius:4px;margin-bottom:3px;border:1px solid transparent;
  transition:all .4s;position:relative;overflow:hidden;}
.sg::before{content:'';position:absolute;left:0;top:0;bottom:0;width:2px;
  background:transparent;transition:background .4s;}
.sg.pend{color:#182018;}
.sg.act{color:var(--yel);background:rgba(15,12,0,.8);border-color:rgba(50,40,0,.6);}
.sg.act::before{background:var(--yel);}
.sg.done{color:#2a6a2a;background:rgba(0,12,0,.5);}
.sg.done::before{background:var(--gd);}
.sg.err{color:var(--red);border-color:rgba(80,0,0,.4);}
.si{width:15px;font-size:11px;flex-shrink:0;margin-top:1px;}
.sn{font-size:9px;line-height:1.4;}
.ss{font-size:8px;margin-top:1px;color:#182018;transition:color .3s;}
.sg.act .ss{color:#3a3010;}.sg.done .sn{color:#3a8a3a;}.sg.done .ss{color:#1c3c1c;}
.spin{display:inline-block;animation:spin .6s linear infinite;}
@keyframes spin{to{transform:rotate(360deg);}}
.disc{font-size:8px;color:#180808;border:1px solid rgba(80,0,0,.3);
  background:rgba(8,2,2,.8);border-radius:3px;padding:8px 11px;
  line-height:1.8;margin:8px 14px 14px;}
.stats{flex-shrink:0;display:grid;grid-template-columns:repeat(4,1fr);
  border-bottom:1px solid var(--bd);
  background:linear-gradient(180deg,rgba(4,8,4,.98),rgba(2,4,2,.95));}
.sc{padding:13px 8px;text-align:center;border-right:1px solid var(--bd);
  cursor:default;transition:transform .4s,box-shadow .4s;}
.sc:last-child{border-right:none;}
.sc:hover{transform:perspective(600px) rotateX(-8deg) rotateY(4deg)
  translateY(-3px) scale(1.02);}
.sv{font-size:22px;font-weight:bold;line-height:1;transition:all .5s;}
.sl{font-size:7px;letter-spacing:2px;color:var(--dim);margin-top:4px;}
.sc.crit .sv{color:#301818;}.sc.high .sv{color:#302010;}
.sc.med  .sv{color:#303010;}.sc.scr  .sv{color:#103020;}
.sc.crit.on .sv{color:var(--red);text-shadow:0 0 15px var(--red);}
.sc.high.on .sv{color:var(--ora);text-shadow:0 0 12px var(--ora);}
.sc.med.on  .sv{color:var(--yel);text-shadow:0 0 10px var(--yel);}
.sc.scr.on  .sv{color:var(--cyn);text-shadow:0 0 12px var(--cyn);}
.score-bar{height:2px;background:#0a1a0a;border-radius:1px;margin-top:6px;overflow:hidden;}
.score-fill{height:100%;width:0;border-radius:1px;
  background:linear-gradient(90deg,var(--red),var(--yel),var(--cyn));
  transition:width 1.5s cubic-bezier(.25,.46,.45,.94);}
.rw{flex:1;display:flex;flex-direction:column;overflow:hidden;}
.rh{display:flex;align-items:center;justify-content:space-between;
  flex-shrink:0;padding:8px 20px;border-bottom:1px solid var(--bd);
  background:rgba(4,8,4,.98);}
.rt{font-size:9px;letter-spacing:2px;color:#2a5a2a;}
.ra{display:flex;gap:7px;}
.db,.dh,.cb{padding:5px 14px;background:transparent;font-family:var(--fn);
  font-size:8px;letter-spacing:1px;border-radius:2px;cursor:pointer;transition:all .25s;}
.db{border:1px solid var(--blu);color:var(--blu);}
.dh{border:1px solid var(--ora);color:var(--ora);}
.db:hover{background:var(--blu);color:#000;}
.dh:hover{background:var(--ora);color:#000;}
.cb{border:1px solid #2a2a2a;color:#3a3a3a;}
.cb:hover{border-color:var(--red);color:var(--red);}
.db:disabled,.dh:disabled{opacity:.2;cursor:not-allowed;}
.rb{flex:1;overflow-y:auto;padding:22px 28px;font-size:12px;
  line-height:1.9;white-space:pre-wrap;color:var(--wht);
  background:rgba(2,4,2,.98);}
.wc{flex:1;display:flex;flex-direction:column;align-items:center;
  justify-content:center;gap:16px;padding:40px;
  background:linear-gradient(135deg,rgba(2,6,2,.98),rgba(4,8,4,.95));}
.wc-ring{position:relative;width:80px;height:80px;
  display:flex;align-items:center;justify-content:center;}
.wc-ring-pulse{position:absolute;width:80px;height:80px;
  border:1px solid var(--gd);border-radius:50%;
  animation:ringPulse 3s ease-out infinite;opacity:0;}
.wc-ring-pulse:nth-child(2){animation-delay:1s;}
.wc-ring-pulse:nth-child(3){animation-delay:2s;}
@keyframes ringPulse{0%{transform:scale(.3);opacity:.8;}100%{transform:scale(2.5);opacity:0;}}
.wc-icon{font-size:36px;position:relative;z-index:1;}
.wt{font-size:11px;letter-spacing:5px;color:#1e361e;text-transform:uppercase;}
.ws{font-size:9px;line-height:2.2;color:#0e1e0e;text-align:center;}
.scan-bar{position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,transparent,var(--g),var(--gd),transparent);
  transform:translateX(-100%);animation:scanBar 2.5s ease-in-out infinite;
  box-shadow:0 0 10px var(--g);display:none;}
.scan-bar.active{display:block;}
@keyframes scanBar{0%{transform:translateX(-100%);}100%{transform:translateX(100%);}}
.btm{flex-shrink:0;padding:5px 20px;border-top:1px solid var(--bd);
  background:rgba(2,4,2,.98);display:flex;align-items:center;gap:14px;}
.bs{font-size:8px;color:#1a2a1a;letter-spacing:1px;transition:color .3s;}
.bs.scanning{color:var(--yel);animation:textPulse 1.5s ease-in-out infinite;}
.bs.done{color:var(--gd);}.bs.err{color:var(--red);}
@keyframes textPulse{0%,100%{opacity:1;}50%{opacity:.5;}}
.br{margin-left:auto;font-size:8px;color:#121a12;}
.gpu-ind{display:flex;align-items:center;gap:5px;font-size:8px;color:#1a3a1a;
  border:1px solid #0e2a0e;padding:3px 8px;border-radius:2px;}
.gpu-dot{width:5px;height:5px;border-radius:50%;background:#1a5a1a;
  animation:gpuPulse 2s ease-in-out infinite;}
@keyframes gpuPulse{0%,100%{background:#1a5a1a;}
  50%{background:var(--gd);box-shadow:0 0 6px var(--gd);}}
::-webkit-scrollbar{width:3px;height:3px;}
::-webkit-scrollbar-track{background:var(--bg);}
::-webkit-scrollbar-thumb{background:linear-gradient(180deg,#1a3a1a,#0e2a0e);border-radius:2px;}
::-webkit-scrollbar-thumb:hover{background:var(--gd);}
</style>
</head>
<body>
<div class="top">
  <div class="logo">⚡VAJRA<em>NET</em></div>
  <div class="pill on">v5.4</div>
  <div class="pill on">GPU</div>
  <div class="pill on">CRAWLER</div>
  <div class="pill on">CLUSTER-404</div>
  <div class="pill" id="pSQLi">SQLi</div>
  <div class="pill" id="pXSS">XSS</div>
  <div class="pill on">OWASP/CWE</div>
  <div class="pill" id="pWAF">-</div>
  <div class="pill" id="pS404">S404:-</div>
  <div class="pill" id="pAuth">AUTH:-</div>
  <div class="top-r">LOCAL · ZERO UPLOAD · WINDOWS</div>
</div>

<div class="body">
  <div class="L">
    <div style="border-bottom:1px solid var(--bd);">
      <div class="ph"><span class="d"></span>TARGET ACQUISITION</div>
      <div class="pb">
        <input class="url-in" id="urlIn" type="text"
               placeholder="https://target.com  or  192.168.x.x"
               spellcheck="false" autocomplete="off"/>

        <div class="auth-box">
          <button class="auth-toggle" onclick="toggleAuth()">
            ⚿ AUTHENTICATED SCAN (optional)
          </button>
          <div class="auth-fields" id="authFields">
            <div class="lbl" style="margin-top:8px">AUTH TYPE</div>
            <select class="sel" id="authType" onchange="updateAuthFields()">
              <option value="">— None —</option>
              <option value="bearer">Bearer Token</option>
              <option value="basic">Basic Auth</option>
              <option value="cookie">Cookie</option>
              <option value="header">Custom Header</option>
            </select>
            <div id="authExtra"></div>
          </div>
        </div>

        <button class="btn" id="scanBtn" onclick="go()">
          [ INITIATE FULL SCAN ]
        </button>
        <div class="hint">
          <b>Crawler</b>(60p) · <b>Headers</b>(10) · <b>SSL/TLS</b> ·
          <b>Nmap</b> · <b>Paths</b>(87) · <b>SQLi</b>(22) · <b>XSS</b>(5) ·
          <b>Nuclei</b> · <b>ZAP</b> · <b>Cluster-404</b> · OWASP/CWE/MITRE
        </div>
      </div>
    </div>

    <div style="border-bottom:1px solid var(--bd);flex:1;position:relative;">
      <div class="scan-bar" id="scanBar"></div>
      <div class="ph"><span class="d"></span>SCAN PROGRESS</div>
      <div style="padding:9px 11px;">
        <div class="sg pend" id="s1"><span class="si">○</span>
          <div><div class="sn">HTTP + Header Analysis</div>
               <div class="ss">Fetch · Parse · Fingerprint</div></div></div>
        <div class="sg pend" id="s2"><span class="si">○</span>
          <div><div class="sn">Crawler + Asset Discovery</div>
               <div class="ss">BFS · Forms · Params · Subdomains</div></div></div>
        <div class="sg pend" id="s3"><span class="si">○</span>
          <div><div class="sn">SSL/TLS Inspection</div>
               <div class="ss">Cert · Protocol · Cipher</div></div></div>
        <div class="sg pend" id="s4"><span class="si">○</span>
          <div><div class="sn">Port Scan + Nmap</div>
               <div class="ss">Socket + service/version detection</div></div></div>
        <div class="sg pend" id="s5"><span class="si">○</span>
          <div><div class="sn">Path Discovery (87+)</div>
               <div class="ss">Cluster-404 + WAF filter</div></div></div>
        <div class="sg pend" id="s6"><span class="si">○</span>
          <div><div class="sn">SQLi + XSS + ZAP + Nuclei</div>
               <div class="ss">Active injection + tool scan</div></div></div>
        <div class="sg pend" id="s7"><span class="si">○</span>
          <div><div class="sn">AI Report + Deduplication</div>
               <div class="ss">GPU LLM · OWASP · CWE · MITRE</div></div></div>
        <div class="sg pend" id="s8"><span class="si">○</span>
          <div><div class="sn">Build HTML + TXT Report</div>
               <div class="ss">Downloadable documents</div></div></div>
        <div class="sg pend" id="s9"><span class="si">○</span>
          <div><div class="sn">Finalize</div>
               <div class="ss">Complete</div></div></div>
      </div>
    </div>
    <div class="disc">
      ⚠ AUTHORIZED USE ONLY — Scan only systems you own or have
      explicit written permission to test.<br/>
      All processing 100% local. Zero data leaves your machine.
    </div>
  </div>

  <div class="R">
    <div class="stats">
      <div class="sc crit" id="scC">
        <div class="sv" id="vC">—</div>
        <div class="sl">CRITICAL</div>
      </div>
      <div class="sc high" id="scH">
        <div class="sv" id="vH">—</div>
        <div class="sl">HIGH</div>
      </div>
      <div class="sc med" id="scM">
        <div class="sv" id="vM">—</div>
        <div class="sl">MEDIUM</div>
      </div>
      <div class="sc scr" id="scS">
        <div class="sv" id="vS">—</div>
        <div class="sl">RISK SCORE</div>
        <div class="score-bar">
          <div class="score-fill" id="scoreFill"></div>
        </div>
      </div>
    </div>

    <div class="rw" id="rw" style="display:none;">
      <div class="rh">
        <div class="rt">📋 SECURITY ASSESSMENT REPORT v5.4</div>
        <div class="ra">
          <button class="db" id="dlBtn" onclick="dl('txt')" disabled>⬇ TXT</button>
          <button class="dh" id="dlHtml" onclick="dl('html')" disabled>⬇ HTML</button>
          <button class="cb" onclick="clr()">✕ CLEAR</button>
        </div>
      </div>
      <div class="rb" id="rb"></div>
    </div>

    <div class="wc" id="wc">
      <div class="wc-ring">
        <div class="wc-ring-pulse"></div>
        <div class="wc-ring-pulse"></div>
        <div class="wc-ring-pulse"></div>
        <div class="wc-icon">🛡</div>
      </div>
      <div class="wt">VajraNet AI Scanner v5.4</div>
      <div class="ws">
        Enter a target URL · Configure auth (optional)<br/>
        Click INITIATE FULL SCAN<br/>
        Cluster-based Soft-404 Detection · Cloudflare Bypass<br/>
        Nmap · Nuclei · ZAP · OWASP/CWE/MITRE<br/>
        No false positives · HTML + TXT reports
      </div>
    </div>
  </div>
</div>

<div class="btm">
  <div class="bs" id="bs">Ready</div>
  <div class="gpu-ind"><div class="gpu-dot"></div><span>GPU ACTIVE</span></div>
  <div id="crawlStat" style="font-size:8px;color:#1a3a1a;"></div>
  <div class="br">VajraNet v5.4 · Cluster-404 Fix · OWASP/CWE/MITRE · GPU</div>
</div>

<script>
let sid=null,tmr=null;
const IC={pend:'○',act:'<span class="spin">⟳</span>',done:'✓',err:'✗'};
function sg(n,s,sub){
  const e=document.getElementById('s'+n);
  if(!e)return;
  e.className='sg '+s;
  e.querySelector('.si').innerHTML=IC[s]||'○';
  if(sub)e.querySelector('.ss').textContent=sub;
}
function rst(){
  for(let i=1;i<=9;i++)sg(i,'pend');
  ['C','H','M','S'].forEach(x=>{
    document.getElementById('v'+x).textContent='—';
    document.getElementById('sc'+x).classList.remove('on');
  });
  document.getElementById('scoreFill').style.width='0';
  ['pSQLi','pXSS'].forEach(id=>{
    const e=document.getElementById(id);
    e.className='pill';e.textContent=id.replace('p','');
  });
  ['pWAF','pS404','pAuth'].forEach(id=>{
    const e=document.getElementById(id);
    e.className='pill';e.textContent=id.replace('p','')+':−';
  });
  document.getElementById('scanBar').classList.remove('active');
  document.getElementById('crawlStat').textContent='';
}
function setS(t,cls){
  const e=document.getElementById('bs');
  e.textContent=t;e.className='bs '+(cls||'');
}
function setBtn(t,d){
  const b=document.getElementById('scanBtn');
  b.textContent=t;b.disabled=d;
}
function toggleAuth(){
  document.getElementById('authFields').classList.toggle('open');
}
function updateAuthFields(){
  const t=document.getElementById('authType').value;
  const ex=document.getElementById('authExtra');
  const inp=(ph,id)=>
    `<input class="auth-in" id="${id}" placeholder="${ph}" autocomplete="off"/>`;
  if(t==='bearer')
    ex.innerHTML='<div class="lbl">TOKEN</div>'+inp('Bearer token','authToken');
  else if(t==='basic')
    ex.innerHTML='<div class="lbl">USERNAME</div>'+inp('Username','authUser')+
      '<div class="lbl">PASSWORD</div>'+inp('Password','authPass');
  else if(t==='cookie')
    ex.innerHTML='<div class="lbl">COOKIE STRING</div>'+
      inp('session=abc; token=xyz','authCookie');
  else if(t==='header')
    ex.innerHTML='<div class="lbl">HEADER NAME</div>'+
      inp('X-Api-Key','authHdrName')+
      '<div class="lbl">HEADER VALUE</div>'+inp('value','authHdrVal');
  else ex.innerHTML='';
}
function getAuthConfig(){
  const t=document.getElementById('authType').value;
  if(!t)return null;
  const g=id=>{const e=document.getElementById(id);return e?e.value.trim():'';};
  if(t==='bearer')  return{type:'bearer',token:g('authToken')};
  if(t==='basic')   return{type:'basic',username:g('authUser'),password:g('authPass')};
  if(t==='cookie')  return{type:'cookie',cookie:g('authCookie')};
  if(t==='header')  return{type:'header',header_name:g('authHdrName'),
                            header_value:g('authHdrVal')};
  return null;
}
async function go(){
  const url=document.getElementById('urlIn').value.trim();
  if(!url){alert('Enter a URL or IP address.');return;}
  const auth=getAuthConfig();
  rst();
  setBtn('[ SCANNING... ]',true);
  setS('Initializing...','scanning');
  document.getElementById('scanBar').classList.add('active');
  document.getElementById('wc').style.display='flex';
  document.getElementById('rw').style.display='none';
  document.getElementById('dlBtn').disabled=true;
  document.getElementById('dlHtml').disabled=true;
  try{
    const r=await fetch('/start-scan',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({url,auth_config:auth})
    });
    if(!r.ok)throw new Error('HTTP '+r.status);
    const d=await r.json();
    sid=d.scan_id;
    clearInterval(tmr);
    tmr=setInterval(poll,1500);
  }catch(e){
    setBtn('[ INITIATE FULL SCAN ]',false);
    setS('Error: '+e.message,'err');
    document.getElementById('scanBar').classList.remove('active');
    alert('Scan failed: '+e.message);
  }
}
async function poll(){
  if(!sid)return;
  try{
    const r=await fetch('/status?id='+sid);
    if(!r.ok)return;
    const d=await r.json();
    const st=d.stage||0;
    for(let i=1;i<=9;i++){
      if(i<st)sg(i,'done');
      else if(i===st)sg(i,'act',d.stage_name||'');
      else sg(i,'pend');
    }
    setS((d.stage_name||d.status||'...'),'scanning');
    if(d.crawl_stats){
      document.getElementById('crawlStat').textContent=
        `crawled:${d.crawl_stats.pages||0} forms:${d.crawl_stats.forms||0}`;
    }
    if(d.status==='done'){
      clearInterval(tmr);
      for(let i=1;i<=9;i++)sg(i,'done');
      document.getElementById('scanBar').classList.remove('active');
      show(d);
      setBtn('[ INITIATE FULL SCAN ]',false);
      setS('✓ Complete — '+new Date().toLocaleTimeString(),'done');
    }else if(d.status==='error'){
      clearInterval(tmr);
      document.getElementById('scanBar').classList.remove('active');
      sg(d.stage||1,'err','Error: '+(d.error||'unknown').slice(0,40));
      setBtn('[ INITIATE FULL SCAN ]',false);
      setS('ERROR: '+(d.error||'unknown').slice(0,60),'err');
    }
  }catch(e){console.error(e);}
}
function ani(vid,scid,val,suf){
  const el=document.getElementById(vid);
  const sc=document.getElementById(scid);
  if(val===0){el.textContent='0'+(suf||'');return;}
  let cur=0;
  const steps=15,step=Math.ceil(val/steps);
  const iv=setInterval(()=>{
    cur=Math.min(cur+step,val);
    el.textContent=cur+(suf||'');
    if(cur>=val){clearInterval(iv);sc.classList.add('on');}
  },60);
}
function show(d){
  const s=d.stats||{};
  ani('vC','scC',s.critical||0,'');
  ani('vH','scH',s.high||0,'');
  ani('vM','scM',s.medium||0,'');
  ani('vS','scS',s.score||0,'/100');
  setTimeout(()=>{
    if(s.score!=null)
      document.getElementById('scoreFill').style.width=(100-s.score)+'%';
  },200);
  if(d.sqli_vuln){
    const p=document.getElementById('pSQLi');
    p.className='pill err';p.textContent='SQLi ✓ VULN';
  }
  if(d.xss_vuln){
    const p=document.getElementById('pXSS');
    p.className='pill err';p.textContent='XSS ✓ VULN';
  }
  const pw=document.getElementById('pWAF');
  if(d.waf_blocked){pw.className='pill warn pulse';pw.textContent='WAF BLOCKED';}
  else{pw.className='pill on';pw.textContent='CF OK';}
  const ps=document.getElementById('pS404');
  const cs=d.cluster_size;
  if(cs){ps.className='pill on';ps.textContent='S404:CLUSTER';}
  else if(d.soft404_available){ps.className='pill on';ps.textContent='S404:OK';}
  else{ps.className='pill warn';ps.textContent='S404:LTD';}
  const pa=document.getElementById('pAuth');
  if(d.auth_used){pa.className='pill on';pa.textContent='AUTH:ON';}
  else{pa.className='pill';pa.textContent='AUTH:OFF';}
  document.getElementById('rb').innerHTML=clr_txt(d.report||'No report.');
  document.getElementById('wc').style.display='none';
  document.getElementById('rw').style.display='flex';
  document.getElementById('dlBtn').disabled=false;
  document.getElementById('dlHtml').disabled=false;
  if(d.crawl_stats){
    document.getElementById('crawlStat').textContent=
      `crawled:${d.crawl_stats.pages} | findings:${d.findings_count||0}`+
      (cs?` | cluster:~${cs}B`:'');
  }
}
function clr_txt(t){
  const e=t.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  return e
    .replace(/\[CRITICAL\]/g,
      '<span style="color:#ff2020;font-weight:bold">[CRITICAL]</span>')
    .replace(/\[HIGH\]/g,
      '<span style="color:#ff7700;font-weight:bold">[HIGH]</span>')
    .replace(/\[MEDIUM\]/g,'<span style="color:#ffd000">[MEDIUM]</span>')
    .replace(/\[LOW\]/g,'<span style="color:#00cc30">[LOW]</span>')
    .replace(/\[INFO\]/g,'<span style="color:#00aaff">[INFO]</span>')
    .replace(/\[HIGH CONF\]/g,
      '<span style="color:#00cc30;border:1px solid #00cc30;padding:1px 4px;border-radius:2px;font-size:9px">[HIGH CONF]</span>')
    .replace(/\[MEDIUM CONF\]/g,
      '<span style="color:#ffd000;border:1px solid #ffd000;padding:1px 4px;border-radius:2px;font-size:9px">[MED CONF]</span>')
    .replace(/\[LOW CONF\]/g,
      '<span style="color:#ff7700;border:1px solid #ff7700;padding:1px 4px;border-radius:2px;font-size:9px">[LOW CONF]</span>')
    .replace(/(OWASP[^\n]*)/gi,'<span style="color:#607060">$1</span>')
    .replace(/(CWE-\d+)/g,'<span style="color:#00aaff">$1</span>')
    .replace(/(T\d{4}(?:\.\d+)?)/g,'<span style="color:#cc8800">$1</span>')
    .replace(/(CONFIRMED VULNERABILITIES)/gi,
      '<span style="color:#ff2020;font-weight:bold;font-size:13px">$1</span>')
    .replace(/(POTENTIAL ISSUES)/gi,
      '<span style="color:#ff7700;font-weight:bold;font-size:13px">$1</span>')
    .replace(/(INFORMATIONAL FINDINGS)/gi,
      '<span style="color:#00aaff;font-weight:bold;font-size:13px">$1</span>')
    .replace(/^(={3,}.*)$/gm,'<span style="color:#1e4a1e">$1</span>')
    .replace(/^(-{3,}.*)$/gm,'<span style="color:#163216">$1</span>')
    .replace(/(Fix\s*:)/gi,
      '<span style="color:#00aaff;font-weight:bold">$1</span>')
    .replace(/(Evidence\s*:)/gi,
      '<span style="color:#bbaa00">$1</span>')
    .replace(/(Impact\s*:)/gi,
      '<span style="color:#cc7700">$1</span>');
}
function clr(){
  document.getElementById('rw').style.display='none';
  document.getElementById('wc').style.display='flex';
  document.getElementById('dlBtn').disabled=true;
  document.getElementById('dlHtml').disabled=true;
  rst();
}
async function dl(fmt){
  if(!sid)return;
  const ep=fmt==='html'?'/download-html?id='+sid:'/download?id='+sid;
  try{
    const r=await fetch(ep);
    if(!r.ok)throw new Error('HTTP '+r.status);
    const b=await r.blob();
    const a=document.createElement('a');
    a.href=URL.createObjectURL(b);
    a.download='VajraNet_Report_'+new Date().toISOString().slice(0,10)+
               (fmt==='html'?'.html':'.txt');
    a.click();
  }catch(e){alert('Download error: '+e.message);}
}
document.addEventListener('DOMContentLoaded',()=>{
  document.getElementById('urlIn').addEventListener('keypress',e=>{
    if(e.key==='Enter')go();
  });
});
</script>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════════
#  HTTP SERVER
# ══════════════════════════════════════════════════════════════════════════════
class H(BaseHTTPRequestHandler):
    def cors(self):
        self.send_header('Access-Control-Allow-Origin','*')
        self.send_header('Access-Control-Allow-Methods','GET,POST,OPTIONS')
        self.send_header('Access-Control-Allow-Headers','*')

    def jsend(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(b)))
        self.cors(); self.end_headers(); self.wfile.write(b)

    def do_OPTIONS(self):
        self.send_response(200); self.cors(); self.end_headers()

    def do_GET(self):
        pp = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(pp.query)
        if pp.path in ('/', ''):
            d = HTML.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type','text/html; charset=utf-8')
            self.send_header('Content-Length',str(len(d)))
            self.end_headers(); self.wfile.write(d)

        elif pp.path == '/status':
            sid = qs.get('id',[''])[0]
            with jobs_lock:
                job = dict(scan_jobs.get(sid,{}))
            if not job:
                self.jsend(404,{'error':'not found'}); return
            self.jsend(200, job)

        elif pp.path == '/download':
            sid = qs.get('id',[''])[0]
            with jobs_lock: doc = doc_store.get(sid,'')
            if not doc: self.send_error(404,'Not found'); return
            raw = doc.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type','text/plain; charset=utf-8')
            self.send_header('Content-Disposition',
                f'attachment; filename="VajraNet_v54_{sid[:8]}.txt"')
            self.send_header('Content-Length',str(len(raw)))
            self.cors(); self.end_headers(); self.wfile.write(raw)

        elif pp.path == '/download-html':
            sid = qs.get('id',[''])[0]
            with jobs_lock: doc = doc_store.get(sid+'_html','')
            if not doc: self.send_error(404,'Not found'); return
            raw = doc.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type','text/html; charset=utf-8')
            self.send_header('Content-Disposition',
                f'attachment; filename="VajraNet_v54_{sid[:8]}.html"')
            self.send_header('Content-Length',str(len(raw)))
            self.cors(); self.end_headers(); self.wfile.write(raw)

        else:
            self.send_error(404)

    def do_POST(self):
        pp = urllib.parse.urlparse(self.path)
        if pp.path != '/start-scan':
            self.send_error(404); return
        try:
            ln   = int(self.headers.get('Content-Length',0))
            if not (0 < ln < 500_000): self.send_error(400); return
            body = self.rfile.read(ln).decode()
            data = json.loads(body)
            url  = data.get('url','').strip()
            if not url: self.jsend(400,{'error':'no url'}); return
            if not url.startswith(('http://','https://')):
                url = 'https://' + url
            auth_config = data.get('auth_config') or None
            sid = str(uuid.uuid4())
            with jobs_lock:
                scan_jobs[sid] = {
                    'scan_id':    sid, 'url': url,
                    'status':     'starting', 'stage': 0,
                    'stage_name': 'Initializing',
                    'crawl_stats':{'pages':0,'forms':0,'param_urls':0},
                }
            threading.Thread(target=run_job,
                             args=(sid, url, auth_config),
                             daemon=True).start()
            print(f"\n{'='*55}")
            print(f"[SCAN] {sid[:8]} → {url} "
                  f"auth={'yes' if auth_config else 'no'}")
            print(f"{'='*55}", flush=True)
            self.jsend(200, {'scan_id': sid})
        except Exception as e:
            print(f"[ERR] {e}", flush=True)
            self.send_error(500, str(e))

    def log_message(self, *a): pass


class VS(ThreadingMixIn, HTTPServer):
    daemon_threads      = True
    allow_reuse_address = True
    timeout             = 180


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main():
    print('\n' + '='*60)
    print('  VAJRANET AI VULNERABILITY SCANNER v5.4')
    print('  FIX: Cluster-based soft-404 | CF crawler bypass')
    print('  FIX: False positive elimination | Score accuracy')
    print('  FIX: Report written once (no duplication)')
    print('='*60)

    cf   = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
    proc = subprocess.Popen([
        LLAMA_SERVER, '-m', MODEL_PATH,
        '--host','127.0.0.1','--port', str(LLAMA_PORT),
        '--batch-size', BATCH_SIZE,
        '-c', CTX, '-t', str(THREADS),
        '--n-gpu-layers', str(GPU_LAYERS),
        '--flash-attn', '-ngl', '999', '--log-disable',
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
       creationflags=cf)

    print('  Loading model into GPU VRAM (20s)...', flush=True)
    time.sleep(20)
    print(f'  llama.cpp ready :{LLAMA_PORT} ({GPU_LAYERS}L GPU offload)',
          flush=True)

    srv = VS(('0.0.0.0', HTTP_PORT), H)
    print(f'\n  ► http://127.0.0.1:{HTTP_PORT}')
    print(f'\n  v5.4 FIXES:')
    print(f'  ✓ Cluster-based soft-404 auto-detection '
          f'(CLUSTER_FRACTION={CLUSTER_FRACTION} BAND=±{CLUSTER_BAND}B)')
    print(f'  ✓ Two-phase path scan: probe all → detect cluster → verdict')
    print(f'  ✓ Extended NON_HTML_PATHS + content checks '
          f'(webshells, backups, SVN, OpenAPI)')
    print(f'  ✓ Cloudflare crawler bypass (extra headers + retry)')
    print(f'  ✓ Score fix: only confirmed real paths counted')
    print(f'  ✓ Report written exactly once (no duplication)')
    print(f'  ✓ Nmap/Nuclei/ZAP graceful skip if not installed')
    print(f'\n  Paths:{len(PATHS)} · SQLi:{len(SQL_PAYLOADS)} · '
          f'XSS:{len(XSS_PAYLOADS)} · Ports:{len(PORTS)} · Subs:{len(SUBS)}')
    print('='*60+'\n', flush=True)

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print('\n  Shutting down...', flush=True)
        proc.terminate()


if __name__ == '__main__':
    main()
