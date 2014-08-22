<?php
echo 'User-Agent: ', $_SERVER['HTTP_USER_AGENT'];
echo '<br>';
echo 'Referer: ', $_SERVER['HTTP_REFERER'];
echo '<br>';

/* Notice that the below will return the URL escaped value and not trigger an XSS. 
	Once I can figure out how to monkeypatch scrapy Request class so it won't URL encode
	the URL, the script will catch this as a vuln. Until then, it's not vulnerable. */
echo 'URL: ', $_SERVER['REQUEST_URI'];
echo '<br>';
echo 'Your cookie: ';
print_r($_COOKIE);
?>
