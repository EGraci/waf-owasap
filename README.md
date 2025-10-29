# waf-owasap basic
## update your sistem
```
sudo apt update && sudo apt upgrade
```
##  download/clone waf owasap
```
git clone https://github.com/coreruleset/coreruleset.git
```
## configurate example rullset
```
sudo mv coreruleset/crs-setup.conf.example coreruleset/crs-setup.conf
```
## last configurate for nginx
```
modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;

Include /etc/modsecurity/coreruleset/crs-setup.conf
IncludeOptional /etc/modsecurity/coreruleset/plugins/*-config.conf
IncludeOptional /etc/modsecurity/coreruleset/plugins/*-before.conf
#Include /usr/share/modsecurity-crs/rules/*.conf
IncludeOptional /etc/modsecurity/coreruleset/plugins/*-after.conf

if ($http_user_agent ~* (Nikto|Nmap|sqlmap|w3af|Metasploit)) {
    return 403;
}
errors.
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
```
## last configurate for apache
```
 <IfModule security2_module>
  Include /etc/modsecurity/coreruleset/crs-setup.conf
  IncludeOptional /etc/modsecurity/coreruleset/plugins/*-config.conf
  IncludeOptional /etc/modsecurity/coreruleset/plugins/*-before.conf
  #Include /usr/share/modsecurity-crs/rules/*.conf
  IncludeOptional /etc/modsecurity/coreruleset/plugins/*-after.conf
</IfModule>
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteCond %{HTTP_USER_AGENT} Nikto [NC,OR]
  RewriteCond %{HTTP_USER_AGENT} Nmap [NC,OR]
  RewriteCond %{HTTP_USER_AGENT} sqlmap [NC,OR]
  RewriteCond %{HTTP_USER_AGENT} w3af [NC,OR]
  RewriteCond %{HTTP_USER_AGENT} Metasploit [NC]
  RewriteRule .* - [F,L]
</IfModule>
<IfModule mod_headers.c>
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
  Header set X-Content-Type-Options "nosniff"
  Header edit Set-Cookie ^(.*)$ $1;HttpOnly
  Header always set X-Content-Type-Options "nosniff"
</IfModule>
```
