# For simplicity, this file contains only the most important settings by
# default. All the other settings are documented here:
#
#     http://doc.scrapy.org/en/latest/topics/settings.html
#

BOT_NAME = 'xsscrapy'

SPIDER_MODULES = ['xsscrapy.spiders']
NEWSPIDER_MODULE = 'xsscrapy.spiders'

#USER_AGENT = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.131 Safari/537.36'
# Get a random user agent for each crawled page
DOWNLOADER_MIDDLEWARES = {'xsscrapy.middlewares.InjectedDupeFilter': 100,
                          'xsscrapy.middlewares.RandomUserAgentMiddleware': 200}
                          #'scrapy.contrib.downloadermiddleware.useragent.UserAgentMiddleware': None, # disable stock user-agent middleware
                          #'xsscrapy.middlewares.Unencode_url': 100', # disable stock user-agent middleware
                          #'scrapy.contrib.downloadermiddleware.cookies.CookiesMiddleware': None, # disable stock cookies middleware
                          #'xsscrapy.middlewares.CookiesMiddleware': 700} # 700 is in the downloader_middlewares_base

COOKIES_ENABLED = True
#COOKIES_DEBUG = True

# prevent duplicate link crawling
#DUPEFILTER_CLASS = 'scrapy.dupefilter.RFPDupeFilter'
DUPEFILTER_CLASS = 'xsscrapy.bloom.BloomURLDupeFilter'

ITEM_PIPELINES = {'xsscrapy.pipelines.XSS_pipeline':100} # Look into what the 100 is doing (I know lower is higher priority, 0-1000)

FEED_FORMAT = 'csv'
FEED_URI = 'vulnerable-urls.txt'

#CONCURRENT_REQUESTS = 12
