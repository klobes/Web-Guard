# RM WebGuard 1.0 — bllokim automatik IP për klobes.al

Modul i pavarur në server, me Fail2ban, settings në JSON dhe bllokime me afat.
Është për konfigurimin e verifikuar Ubuntu 22.04: Apache, VirtualHost `*:5555`,
`ServerName klobes.al`, `DocumentRoot /var/www/html/public_html` dhe Cloudflare Tunnel lokal.

## Çfarë bën

1. Apache refuzon rrugët e njohura të skanimit me përgjigjen e thjeshtë `403`, përpara `index.php`.
2. Apache merr IP-në nga `CF-Connecting-IP` vetëm kur lidhja vjen nga proxy lokal `127.0.0.1` ose `::1`.
3. Një log i veçantë për portën 5555 përdor IP-në reale, metodën, rrugën dhe statusin. Nuk regjistron query strings, cookies ose Authorization.
4. Fail2ban zbulon pragun e konfiguruar dhe regjistron vendimin.
5. Në mënyrën ENFORCE: bllokon trafikun e drejtpërdrejtë TCP 5555 në firewall lokal dhe IP-në në Cloudflare për zonën e konfiguruar.
6. Fail2ban zhbllokon pas afatit. Një timer riprovon veprimet e Cloudflare që dështuan.

Nuk është identifikim i pagabueshëm “njeri/bot”. Përdor sinjale konkrete dhe pragje;
një `404` e zakonshme për `favicon.ico`, kërkesat e dashboard-it ose një User-Agent
që nuk është shfletues nuk shkaktojnë bllokim në rregullat e skanimit.

## Defaults

| Rregulli | Kushti | Afati |
|---|---|---|
| `rm-web-probes` | 3 kërkesa 403/404 për rrugë skanimi në 60 sekonda | 3600 sekonda / 1 orë |
| `rm-web-sensitive` | 1 tentativë 403/404 për `.env*`, `.git` ose `wp-config.php` | 3600 sekonda / 1 orë |
| `rm-web-flood` | 60 GET/HEAD për `/` në 10 sekonda | 600 sekonda; **fillimisht i çaktivizuar** |

Monitorimi është default: `dry_run=true`. Apache refuzon rrugët e skanimit,
por nuk krijohen bllokime IP në firewall ose Cloudflare derisa të aktivizohet ENFORCE.

Klientët pas CGNAT mund të ndajnë një IP. Për këtë arsye kufizimi i përgjithshëm
fillon i çaktivizuar; pragjet duhen përshtatur sipas trafikut normal.

## Instalimi

Ngarko `RM_WEBGUARD_1.0.tar.gz` në `/tmp` të serverit dhe ekzekuto:

```bash
tar -xzf /tmp/RM_WEBGUARD_1.0.tar.gz -C /tmp
cd /tmp/RM_WEBGUARD_1.0
sudo bash install.sh
```

Duhet të jenë të instaluara dhe funksionale: Python 3, Apache me `mod_rewrite`,
systemd, curl, Fail2ban >= 0.11 dhe `fail2ban-regex`.
Instaluesi ndalon përpara ndryshimeve nëse mungon Fail2ban ose ai nuk është aktiv.
Nëse nuk është i instaluar, instaloje me paketat e Ubuntu:

```bash
sudo apt install fail2ban
sudo systemctl enable --now fail2ban
```

Për bllokim lokal në ENFORCE duhet edhe `iptables` dhe e drejta për të menaxhuar
firewall-in. Nëse serveri është container pa këtë të drejtë, mund të përdorësh
`local_firewall=false` dhe vetëm bllokimin në Cloudflare.

Instalimi kryen:

- kontrollin fillestar të Apache dhe Fail2ban;
- backup të VirtualHost-it në `/var/backups/rm-apache-scan-guard/`;
- futjen e një Include vetëm brenda `*:5555`;
- kontrollin e sintaksës përpara reload-it të Apache;
- kontrollin që `/` mbetet `200`, dhe rrugët e skanimit bëhen `403`;
- kontrollin e IP-së së rivendosur në log me adresë dokumentimi, pa bllokuar vizitor real;
- 8 kërkesa sintetike pozitive/negative për filtrat, përmes `fail2ban-regex` në serverin real;
- kontrollin e konfigurimit të Fail2ban përpara reload-it;
- aktivizimin e timer-it të riprovimit.

Prisni `LIVE_FILTER_TESTS=PASS`, `SETTINGS=PASS MODE=MONITOR` dhe `INSTALL=PASS`.
Nëse provat e Apache dështojnë, konfigurimi i tij kthehet automatikisht.
Nëse konfigurimi i Fail2ban dështon gjatë apply, rikthehet konfigurimi i mëparshëm.

## Settings dhe përjashtimet

```bash
sudo nano /etc/rm-webguard/settings.json
sudo rm-webguard apply
```

| Setting | Kuptimi |
|---|---|
| `enabled` | Aktivizon ose çaktivizon zbulimin automatik |
| `dry_run` | `true`: vetëm monitorim; `false`: bllokim real |
| `local_firewall` | Bllokon edhe lidhjet e drejtpërdrejta në TCP 5555 në ENFORCE |
| `ignoreip` | IP/CIDR të përjashtuara; pa emra DNS |
| `jails.*.maxretry` | Sa kërkesa duhen për vendimin |
| `jails.*.findtime` | Dritarja e vëzhgimit, në sekonda |
| `jails.*.bantime` | Afati fillestar i bllokimit, në sekonda |
| `increment_bantime` | Rrit afatin për përsëritës sipas historikut të Fail2ban |
| `maximum_bantime_seconds` | Kufiri maksimal i afatit; default 86400 / 24 orë |
| `jails.rm-web-flood.enabled` | Aktivizon zbulimin e kërkesave të shumta për faqen kryesore |

Për shembull: `bantime=900` është 15 minuta; `1800` është 30 minuta; `3600` është 1 orë.
Ndryshimet e afatit përdoren për bllokimet e reja; nuk nënkuptojnë shkurtim automatik të çdo bllokimi ekzistues.

Shto IP-në publike të administrimit tënd te `ignoreip` përpara aktivizimit real.
Duhet IP-ja nga e cila shfletuesi yt hyn në faqe; IP-ja publike e serverit nuk
është domosdoshmërisht IP-ja jote. Rrjetet private dhe loopback përjashtohen në defaults.

`instance_id` identifikon rregullat që krijon ky modul. Mos e ndrysho.
Mos ndrysho `zone_id` kur ka bllokime ekzistuese; fillimisht zhbllokoji ose çaktivizo modulin.
`active.json` është konfigurimi i validuar: edito `settings.json`, pastaj përdor `apply`.

## Aktivizimi i bllokimit në Cloudflare

1. Gjej Zone ID të `klobes.al` në Cloudflare.
2. Krijo një API Token për menaxhimin e IP Access rules. Referenca aktuale e API-së
   liston `Account Firewall Access Rules Write`; kufizo token-in te llogaria përkatëse.
   Moduli përdor vetëm endpoint-in `/zones/<zone_id>/...`, jo `/accounts/...` ose `/user/...`.
   Kontrolli i mëposhtëm vërteton në praktikë leximin, krijimin dhe fshirjen në atë zonë.
3. Ruaje token-in në server përmes prompt-it të fshehur:

```bash
sudo rm-webguard token
```

Token-i ruhet vetëm në `/etc/rm-webguard/cloudflare.token`, pronësi root, me leje 600.
Mos e dërgo në chat dhe mos e vendos në komandë si argument.

4. Vendos `zone_id`, IP-të e tua te `ignoreip` dhe `dry_run=false` te settings.
5. Ekzekuto:

```bash
sudo rm-webguard apply
sudo rm-webguard status
```

`apply` teston leximin/krijimin/fshirjen në Cloudflare me IP-në e dokumentimit
`198.51.100.23`; ajo nuk i përket një vizitori real në internet. Pastaj validon
Fail2ban dhe aktivizon parametrat. Nëse verifikimi dështon, konfigurimi aktiv kthehet.
Nëse token-i ka vetëm lexim ose mungon e drejta për shkrim, ENFORCE nuk pranohet.

Bllokimi i Cloudflare vlen për IP-në në **të gjithë zonën e konfiguruar**, përfshirë
subdomain-et e saj; nuk është rregull vetëm për një hostname. Firewall-i lokal është
i kufizuar në TCP 5555. Kohët dhe vendimet janë në server; funksionimi i API-së është
i nevojshëm për të aplikuar dhe hequr bllokimet në Cloudflare.

## Rregullat ekzistuese në Cloudflare

Mbaje `OFFLINE-PERKOHESISHT` deri sa instalimi dhe verifikimi në ENFORCE të kalojnë.
Pastaj mund të çaktivizosh këtë rregull dhe të vëzhgosh CPU-në.

Kërkesat që bllokohen nga `BLOCK-SCANNERS` në Cloudflare **nuk arrijnë në log-un
e Apache**, prandaj nuk përdoren si sinjal nga ky modul. Mund ta mbash atë rregull
si mbrojtje të parë; nëse do që të njëjtat tentativa të shkaktojnë edhe bllokim IP,
pas provave në ENFORCE çaktivizo vetëm këtë rregull të dyfishuar. Apache vazhdon t'i
refuzojë ato me 403 pa PHP dhe Fail2ban zbulon IP-në. Mbaje rate limiting në Cloudflare.

## Statusi, zhbllokimi dhe çaktivizimi

```bash
sudo rm-webguard status
sudo fail2ban-client status rm-web-probes
sudo journalctl -u fail2ban -u rm-webguard-reconcile.service -n 60 --no-pager
sudo tail -n 30 /var/log/rm-webguard/access.log
```

Në MONITOR, `WOULD_BAN` është vendim hipotetik, jo bllokim real. Fail2ban mund të
shfaqë IP si “banned” në numëruesin e vet edhe në këtë mënyrë; kontrollo `dry_run`
dhe `edge` te `rm-webguard status`. Në ENFORCE, `BAN_REQUESTED` është kërkesë në
pritje; `BAN_EDGE` dhe statusi `active` konfirmojnë krijimin/gjetjen e rregullit në Cloudflare.

Për një IP të vetme:

```bash
sudo rm-webguard unban IP_E_VERTETE
```

Zhbllokimi manual pastron vendimet në rregullat e modulit; nëse IP-ja vazhdon sjelljen,
mund të bllokohet përsëri. Për përjashtim të qëndrueshëm, shtoje te `ignoreip` dhe bëj `apply`.

```bash
sudo rm-webguard disable
```

`disable` ndalon detector-in, pastron vendimet dhe kërkon heqjen e bllokimeve të vet.
Refuzimet e thjeshta të rrugëve nga Apache mbeten derisa të kryhet `remove`.

```bash
sudo rm-webguard remove
```

`remove` heq Include-in e Apache dhe çaktivizon timer-in vetëm kur rregullat e veta
në Cloudflare janë pastruar. Nëse ka shumë rregulla ose API nuk përgjigjet, timer-i
mbahet aktiv dhe komanda duhet përsëritur pasi pastrimi të përfundojë. Settings,
kodi dhe historiku ruhen për kontroll. Rregullat manuale në Cloudflare nuk fshihen.

Në gjendje normale, heqja në Cloudflare ndodh te afati ose brenda intervalit të
timer-it/riprovimit. Kur API nuk është e arritshme, bllokimi në Cloudflare mund të
zgjasë përtej afatit deri sa komunikimi të rikthehet; timer-i vazhdon riprovimin.

## Verifikimi i paketës

```bash
python3 tests.py
```

24 teste offline kaluan: pragjet e filtrave/normal traffic, whitelist, IPv4/IPv6,
afatet, dy rregulla për të njëjtën IP, instalim i kthyeshëm i Include-it,
bllokim vetëm në TCP 5555, gabime API dhe humbja e përgjigjes pas krijimit të rregullit.
API-ja dhe firewall-i real nuk u thirrën nga këto teste. Apache dhe Fail2ban nuk
janë të instaluara në mjedisin ku u përgatit paketa; provat reale bëhen nga instaluesi
në server. Nuk është bërë instalim ose aktivizim në serverin tënd nga ky chat.

## Referenca

- [Fail2ban dhe konfigurimi](https://github.com/fail2ban/fail2ban/blob/master/config/jail.conf)
- [Cloudflare IP Access rules API](https://developers.cloudflare.com/api/resources/firewall/subresources/access_rules/)
- [Cloudflare HTTP headers](https://developers.cloudflare.com/fundamentals/reference/http-headers/)
- [Apache mod_remoteip](https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html)
- [Apache refuzimi F](https://httpd.apache.org/docs/2.4/rewrite/flags.html#flag_f)
