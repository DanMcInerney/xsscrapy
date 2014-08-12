xsscrapy
========

From within the main folder run:

```scrapy crawl xsscrapy -a url='http://something.com'```


If you wish to login then crawl:

```scrapy crawl xsscrapy -a url='http://something.com/login_page' -a login=username -a pw=secret_password```

Output is stored in formatted-urls.txt.
