# RM WebGuard — Botble plugin 1.2.0

Plugin i pavarur `web-guard` për MartFury / Botble: dashboard, tabela, settings,
permissions dhe agent lokal që komandon motorin mbrojtës të serverit.

U përshtat nga struktura reale e arkivit MartFury: provider, plugin.json, menusë,
ACL dhe aktivizimit Botble, Laravel 12 dhe PHP >= 8.2. Destinacioni është Ubuntu 22.04,
Apache prefork + PHP, VirtualHost `*:5555`, `klobes.al`, DocumentRoot
`/var/www/html/public_html`, projekti `/var/www/html/MartFury` dhe Cloudflare Tunnel lokal.

## Paneli

| Ekrani | Funksionet |
|---|---|
| Dashboard | CPU/load, tentativa në 24h, grafik për orë, IP-të me më shumë tentativa, Fail2ban/Cloudflare/agenti |
| Incidentet | IP, koha, rruga, metoda, HTTP status, rregulli dhe vendimi; filtra dhe pagination |
| Bllokimet | active, pending, pending_unban, released; afati, konfirmimi i fundit dhe zhbllokim manual |
| Përjashtimet | IP/CIDR dhe përshkrim; aplikim edhe mbi bllokimet ekzistuese të modulit |
| Rregullat | Pragjet e rregullave (kërkesa, afati, bllokimi) dhe lista dinamike e rrugëve të skanimit (segment ose prapashtesë), e ruajtur në DB dhe e dërguar te Fail2ban pas provës |
| Instalimi | 8 hapa me gjendje live, komanda me buton Kopjo; hapet vetë kur motori nuk është lidhur |
| Settings | MONITOR/ENFORCE, aktivizimi, pragjet, afatet, përsëritësit, Zone ID |
| Komandat / Audit | Kërkuesi, komanda, prova, rezultati dhe revision-i i kërkuar / i aplikuar |

`PREVIEW.html` është pamje demonstrimi me të dhëna shembull, jo statistika nga serveri.
Numrat dhe grafiku rifreskohen çdo 10 sekonda; tabelat rifreskohen kur hapet faqja.
Agenti dërgon ngjarje dhe gjendje çdo rreth 5 sekonda.

## Gjuha / Language

Paneli ka dy gjuhë, **shqip (`sq`) dhe anglisht (`en`)**, dhe ndjek gjuhën e administrimit të Botble (zgjedhja e gjuhës së përdoruesit). Gjuhët e tjera shfaqin anglisht. Tekstet janë te `web-guard/resources/lang/{sq,en}/web-guard.php`; për një gjuhë tjetër kopjo njërin skedar te `resources/lang/<kodi>/` dhe përkthe vlerat (çelësat dhe `:placeholder` nuk ndryshohen). Mesazhet e motorit në server (log-u, rezultatet te Komandat / Audit) mbeten në shqip.

The panel is available in **Albanian (`sq`) and English (`en`)** and follows the Botble admin language. Other languages fall back to English. Texts live in `web-guard/resources/lang/{sq,en}/web-guard.php`. Engine messages on the server (logs, results under Commands / Audit) stay in Albanian.

## Instalimi

Ngarko paketën në `/tmp`. Nëse mungon Fail2ban:

```bash
sudo apt install fail2ban
sudo systemctl enable --now fail2ban
```

Pastaj:

```bash
tar -xzf /tmp/RM_WEBGUARD_BOTBLE_1.2.0.tar.gz -C /tmp
sudo bash /tmp/RM_WEBGUARD_BOTBLE_1.2.0/install.sh /var/www/html/MartFury
```

Paketa përfshin plugin-in, motorin dhe bridge. Mos instalo veçmas paketën e mëparshme 1.0.
Nëse ajo është instaluar, përdoren të njëjtat jails, instance_id, settings dhe bans;
konfigurimi ekzistues importohet në panel.

Instaluesi kontrollon PHP/Apache/Fail2ban, bën PHP lint, kopjon vetëm plugin-in e ri dhe
assets e tij, migron vetëm 8 tabelat e tij, aktivizon përmes komandës Botble si www-data,
kompilon Blade për kontroll, verifikon routes/permissions/tabelat/CIDR/HMAC dhe provon
Apache, IP-në reale, filtrat Fail2ban dhe sync lokal. Nuk ekzekuton komanda të radhës
gjatë kontrollit të lidhjes. Në fund aktivizon shërbimin e bridge dhe timer-in e motorit.

Prisni `BOTBLE_SELF_TEST=PASS`, `LIVE_FILTER_TESTS=PASS`, `PANEL_SYNC=PASS` dhe
`BOTBLE_INSTALL=PASS`. Instalimi i ri fillon `MODE=MONITOR`; një konfigurim ekzistues
mund të importohet në ENFORCE ose DISABLED.

Nëse ndonjë kontroll dështon, instalimi nuk deklarohet i përfunduar. Backup-et:
`/var/backups/rm-webguard-botble/` dhe `/var/backups/rm-apache-scan-guard/`.
Apache kthehet nëse provat e tij dështojnë; apply i dështuar rikthen settings aktive,
jails dhe input-in e mëparshëm. Tabelat/historiku ruhen. Instalimi i plotë nuk është
një transaksion i vetëm me rollback të të gjitha fazave.

Në Botble shfaqet menuja **Web Guard**, me prefix-in ekzistues, p.sh. `/admin/web-guard`.
Superuser ka akses; për të tjerët cakto lejet e veçanta. Kontrolli është global për
serverin/zonën; nuk është i ndarë sipas company_id.

## Përditësimi i një instalimi ekzistues

Shpaketo paketën e re (jo mbi dosjen e vjetër), hyr në të dhe ekzekuto:

```bash
tar -xzf /tmp/RM_WEBGUARD_BOTBLE_1.2.0.tar.gz -C /tmp
cd /tmp/RM_WEBGUARD_BOTBLE_1.2.0 && sudo bash update.sh /var/www/html/MartFury
```

`update.sh` teston offline, bën kopje rezervë te `/var/backups/rm-webguard-update/`, përditëson motorin, plugin-in,
migron, publikon assets dhe rinis bridge. Nuk prek settings, token-in Cloudflare, bllokimet ose Apache. Prit `UPDATE=PASS`.
`install.sh` mund të përdoret edhe mbi instalim ekzistues; tani përditëson plugin-in në vend që ta refuzojë.
Për një faqe me domain tjetër nga `klobes.al` përdor `RM_SITE_HOST=domain.com sudo -E bash install.sh ...`.

## Çfarë ka ndryshuar nga 1.1.0

- Faqja **Rrugët**: rrugë skanimi të ruajtura në `wg_paths`; motori ndërton vetë regex-in, e provon me `fail2ban-regex`
  kundër rrugëve të ligjshme dhe kthen prapa nëse dështon. Rrugët e rezervuara (`admin`, `login`, `api`...) refuzohen.
- Faqja **Instalimi** me udhëzimet e plota dhe gjendjen e secilit hap.
- `cf_action.py` verifikon që Zone ID i takon domain-it të faqes (kap Account ID të ngatërruar); i anashkalon vetëm kur token-i s'ka Zone Read.
- Migrimi përdor `useCurrent()` për kolonat `timestamp NOT NULL` (MySQL me `explicit_defaults_for_timestamp=OFF` jepte gabimin 1067).
- Shërbimi `rm-webguard-panel` ka leje shkrimi te `/etc/fail2ban/filter.d` dhe `/var/log`.
- Përmirësime në bridge: incidentet përdorin listën me rrugët e reja.

## Mënyra emergjente (sulm masiv)

Settings → **Mënyra emergjente**: Apache u përgjigjet vetëm IP-ve te Përjashtimet (dhe 127.0.0.1); të tjerët marrin 403.
Dy nivele: **Vetëm /admin** (faqja mbetet e hapur) ose **Gjithë faqja**. Është gjithmonë e kohëzuar (5 minuta deri 24 orë) dhe
hiqet vetë. Nuk kërkon leje shtesë në Cloudflare: përdor `Require ip` te Apache me IP-në reale nga `mod_remoteip`.
Paneli refuzon aktivizimin kur lista e përjashtimeve është bosh ose IP-ja jote nuk është në të (nëse nuk konfirmon).
Dalje urgjente nga serveri: `sudo rm-webguard lockdown-off`. Skedari: `/etc/apache2/rm-guards/lockdown-5555.conf`, i përfshirë me një bllok të vogël me shenja (`RM-WEBGUARD-LOCKDOWN-5555`) brenda `VirtualHost *:5555`; `update.sh` e shton një herë, me kopje rezervë dhe rikthim (`sudo rm-webguard lockdown-install` për ta përsëritur).
Kufi: sulmi arrin ende deri te tuneli dhe Apache; mbron aplikacionin dhe databazën, jo brezin. Për brezin përdor Cloudflare WAF.

## Rrugët e panelit te Apache (403 para PHP)

Çdo rrugë aktive te **Rregullat** shkruhet edhe si rregull `RewriteRule ... [F,L]` te `/etc/apache2/rm-guards/custom-paths-5555.conf`
(përfshirë me të njëjtin bllok `RM-WEBGUARD-LOCKDOWN-5555` te vhost-i `*:5555`). Kërkesa refuzohet me 403 para Laravel, pra nuk
shpenzon CPU-n e aplikacionit, dhe Fail2ban e numëron si më parë. Pas çdo ndryshimi motori bën `configtest`, reload dhe provë të
drejtpërdrejtë (faqja kryesore nuk duhet të jetë 403, rruga e re duhet të jetë 403); nëse dështon, kthen gjithçka.
Rindërtim manual: `sudo rm-webguard paths-sync`.

## Aktivizimi dhe defaults

Në instalim të ri: **MONITOR**. Apache refuzon rrugët e skanimit përpara PHP, por
vendimet IP janë vetëm WOULD_BAN. Një 404 e zakonshme, dashboard-i RadiusManager ose
User-Agent jo-shfletues nuk mjaftojnë për bllokim.

| Rregulli | Pragu | Afati |
|---|---|---|
| rm-web-probes | 3 kërkesa për rrugë skanimi në 60 sekonda | 3600 sekonda |
| rm-web-sensitive | 1 tentativë .env*, .git, wp-config.php | 3600 sekonda |
| rm-web-flood | 60 GET/HEAD për / në 10 sekonda | 600 sekonda; fillimisht joaktiv |

1. Shto IP-në publike të administrimit te **Përjashtimet** dhe prit konfirmimin e settings.
2. Krijo API Token Cloudflare për shkrim IP Access rules. Referenca aktuale liston
   `Account Firewall Access Rules Write`; kufizoje te llogaria përkatëse.
3. Ruaje vetëm në server me prompt-in e fshehur:

```bash
sudo rm-webguard token
```

4. Vendos Zone ID te **Settings**, çaktivizo “Vetëm monitorim” dhe ruaj.
5. Kontrollo **Komandat / Audit** dhe revision-in e aplikuar. Përpara ENFORCE, motori
   provon read/create/delete në Cloudflare me IP dokumentimi që nuk i përket një vizitori real.

Pragjet, maxretry/findtime/bantime, whitelist dhe rritja e afatit për përsëritës ndryshohen
nga paneli. Ruajtja dërgon një revision të kërkuar; ai bëhet aktiv vetëm pas validimit
nga agenti. Gabimet dhe mungesa e lidhjes shfaqen në panel. Sekreti Cloudflare nuk ruhet në DB.

Bllokimi Cloudflare vlen për **të gjithë zonën**, përfshirë subdomain-et. Kodi përdor vetëm
endpoint-in e zonës dhe prek vetëm rregullat me identitetin e vet. Firewall-i lokal prek
vetëm TCP 5555; trafiku Tunnel bllokohet në Cloudflare me IP-në reale. Kur API nuk përgjigjet,
zhbllokimi mund të zgjasë përtej afatit; timer-i vazhdon riprovimin. Rregulli flood fillon
joaktiv sepse klientët pas CGNAT mund të ndajnë IP. Nuk është identifikim i pagabueshëm njeri/bot.

## Tabelat dhe lidhja me motorin

| Tabela | Përmbajtja |
|---|---|
| wg_configurations | Settings të kërkuara dhe të konfirmuara; revisions |
| wg_agents | Heartbeat, CPU/load, gjendje dhe gabime |
| wg_events | Incidentet/vendimet, event ID unik |
| wg_bans | Gjendja e fundit për IP |
| wg_allowlist | IP/CIDR të përjashtuara |
| wg_commands | Komanda, lease, prova, rezultat, kërkues |
| wg_audit | Veprimet administrative |
| wg_nonces | Mbrojtja nga ripërdorimi i kërkesave HMAC |

PHP nuk ekzekuton sudo/shell dhe nuk shkruan settings e root. API-ja lokale përdor HMAC
SHA-256, loopback, afat 60 sekonda dhe nonce unik. Agenti pranon vetëm apply_settings dhe
unban; IP/settings validohen, URL-ja dhe komandat janë të fiksuara. Admin routes kanë ACL
 dhe CSRF. Menuja nuk jep automatikisht lejen për settings ose zhbllokim.

Token-i Cloudflare mbetet root/600. Bridge key është root:www-data/640, direktoria
/etc/rm-webguard është root:www-data/750; settings dhe token-i Cloudflare mbeten root/600.
PHP lexon vetëm bridge key për HMAC dhe të dhënat e DB.

Ngjarjet dërgohen nga SQLite root në batches; event ID-të shmangin dublimin nga riprovimi
 i transportit. Radha ka kufi 50 000 evente. Në tejkalim hiqen të vjetrat dhe dashboard-i
shfaq dropped_events. Incidentet fillojnë nga instalimi; log-et e vjetra nuk importohen.
Motori dhe afatet vazhdojnë kur paneli nuk përgjigjet.

Historiku pastrohet pas 30 ditësh nga Laravel scheduler-i ekzistues: web-guard:prune
në 03:20. Bans aktive dhe komandat në pritje ruhen. Ndrysho retention_days në konfigurimin
 e publikuar të plugin-it për afat tjetër; komandë manuale:

```bash
cd /var/www/html/MartFury
sudo -u www-data php artisan web-guard:prune --days=90
```

Kërkesat e bllokuara që në Cloudflare nuk arrijnë në Apache dhe nuk shfaqen si incidente
këtu. Ky version nuk importon Cloudflare Security Events. WAF/rate limiting mund të mbeten
aktive; shiko engine/README.md për ndërveprimin me BLOCK-SCANNERS/OFFLINE.

## Kontroll dhe çaktivizim

```bash
sudo systemctl status rm-webguard-panel.service --no-pager
sudo journalctl -u rm-webguard-panel.service -n 50 --no-pager
sudo rm-webguard status
cd /var/www/html/MartFury
sudo -u www-data php artisan web-guard:self-test
```

403 gjatë sync: kontrollo key/lejimet dhe destinacionin lokal. 404: DocumentRoot 5555
mund të përdorë projekt tjetër nga rruga e dhënë. Mos ndrysho DocumentRoot pa verifikim;
dërgo output-in e instaluesit për korrigjim.

Çaktivizimi i plugin-it në Botble çaktivizon panelin. Për ndalim të plotë:

```bash
sudo systemctl disable --now rm-webguard-panel.service
sudo rm-webguard disable
```

Për pastrim të rregullave të veta Cloudflare dhe heqjen e guard-it Apache:

```bash
sudo rm-webguard remove
```

Nëse pastrimi është në pritje, timer-i mbahet aktiv; përsërit komandën pas konfirmimit.
Pastaj çaktivizo plugin-in në Botble. Tabelat/audit nuk fshihen automatikisht. Rikthimi i
 të njëjtit version i përdor sërish. migrate:rollback fshin tabelat e migrimit dhe nuk
është mënyra për çaktivizim të zakonshëm.

## Validimi

Kaluan **39 teste offline** (24 motor + 15 bridge) në 1.1.0; 1.2.0 shton `tests_paths.py` (14 teste për rrugët dhe lejet e shërbimit). Afate, whitelist, IPv4/IPv6,
humbje përgjigjesh, retry, komanda të dyfishuara, shell injection te IP, rollback settings,
jails joaktive, rotacion log-u dhe refuzim destinacionesh të jashtme. Kaluan sintaksa
Python 3.10, Bash dhe JavaScript.

PHP/Apache/Fail2ban dhe browser-i nuk janë të instaluar këtu. Nuk është kryer boot/instalim
real Botble ose test real API/firewall. Instaluesi kryen PHP lint, Blade compilation,
testet e tabelave/routes/HMAC dhe provat Apache/Fail2ban/sync në serverin tënd.

Referenca: [Botble](https://docs.botble.com/cms/plugin-structure.html),
[Fail2ban](https://github.com/fail2ban/fail2ban/blob/master/config/jail.conf),
[Cloudflare IP Access API](https://developers.cloudflare.com/api/resources/firewall/subresources/access_rules/),
[Apache mod_remoteip](https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html).
