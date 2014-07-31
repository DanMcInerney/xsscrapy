xsscrapy
========

From within the main folder run:

```scrapy crawl xss_spider -a url='http://something.com'```


If you wish to login then crawl:

```scrapy crawl xss_spider -a url='http://something.com/login_page' -a login=username -a pw=secret_password```

Vulnerable URLs and information are stored as scrapy items in vulnerable-urls.txt and a more readable list in formatted-vulns.txt



Output is stored in a human-readable format in formatted-urls.txt and the csv output is in vulnerable-urls.txt should any vulnerabilities be found.
