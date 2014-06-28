xsscrapy
========

From within the main folder run:

```scrapy crawl xss_spider -a url='http://something.com'```


If you wish to login then crawl:

```scrapy crawl xss_spider -a url='http://something.com/login_page' -a login='username' -a pw='secret_password'```
