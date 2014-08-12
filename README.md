xsscrapy
========

From within the main folder run:

```scrapy crawl xsscrapy -a url='http://something.com'```


If you wish to login then crawl:

```scrapy crawl xsscrapy -a url='http://something.com/login_page' -a login=username -a pw=secret_password```

Vulnerable URLs and information are stored as scrapy items in vulnerable-urls.txt and a more readable list in formatted-vulns.txt


Output is stored in formatted-urls.txt.
