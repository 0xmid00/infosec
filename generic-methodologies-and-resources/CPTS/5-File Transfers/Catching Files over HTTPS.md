There is nothing worse than being on a penetration test, and a client's network IDS picks up on a sensitive file being transferred over plaintext and having them ask why we sent a password to our cloud server without using encryption. so will cover creating a secure web server for file upload operations.
## Nginx - Enabling PUT

```bash
# Create a Directory to Handle Uploaded Files
sudo mkdir -p /var/www/uploads/SecretUploadDirectory
#  Change the Owner to www-data
sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory

# Create Nginx Configuration File `/etc/nginx/sites-available/upload.conf`

server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}

# Symlink our Site to the sites-enabled Directory
sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/ 
# Start Nginx
sudo systemctl restart nginx.service
```
>If we get any error messages, check `/var/log/nginx/error.log`. If using Pwnbox, we will see port 80 is already in use.
```bash
# Verifying Errors
tail -2 /var/log/nginx/error.log #=> (`ddress already in use`)
ss -lnpt | grep 80 #=>  .0.0.0:80        0.0.0.0:*    users:(("python",pid=`2811`,fd=3)
ps -ef | grep 2811 #=>  python -m websockify 80 localhost:5901 -D

# We see there is already a module listening on port 80
# To get around this, we can remove the default Nginx configuration, which binds on port 80.
sudo rm /etc/nginx/sites-enabled/default

```

### Upload File Using cURL
```bash
curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt
#check the uploaded file:
udo tail -1 /var/www/uploads/SecretUploadDirectory/users.txt 
```