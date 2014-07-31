# For simplicity, this file contains only the most important settings by
# default. All the other settings are documented here:
#
#     http://doc.scrapy.org/en/latest/topics/settings.html
#

BOT_NAME = 'xsscrapy'

SPIDER_MODULES = ['xsscrapy.spiders']
NEWSPIDER_MODULE = 'xsscrapy.spiders'

# Crawl responsibly by identifying yourself (and your website) on the user-agent
#USER_AGENT = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.131 Safari/537.36'
# Get a random user agent for each crawled page
USER_AGENT_LIST = ['Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.131 Safari/537.36',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.131 Safari/537.36',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/537.75.14',
                   'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20100101 Firefox/29.0',
                   'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.137 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0']
DOWNLOADER_MIDDLEWARES = {'xsscrapy.middlewares.RandomUserAgentMiddleware': 400,
                          'scrapy.contrib.downloadermiddleware.useragent.UserAgentMiddleware': None, # disable stock user-agent middleware
                          'scrapy.contrib.downloadermiddleware.cookies.CookiesMiddleware': None, # disable stock cookies middleware
                          'xsscrapy.middlewares.CookiesMiddleware': 700} # 700 is in the downloader_middlewares_base

COOKIES_ENABLED = True

# prevent duplicate link crawling
DUPEFILTER_CLASS = 'scrapy.dupefilter.RFPDupeFilter'

ITEM_PIPELINES = {'xsscrapy.pipelines.XSS_pipeline':100} # Look into what the 100 is doing (I know lower is higher priority, 0-1000)

FEED_FORMAT = 'csv'
FEED_URI = 'vulnerable-urls.txt'
#COOKIES_DEBUG = True

CONCURRENT_REQUESTS = 12

# Test for injection via headers
#DEFAULT_REQUEST_HEADERS = {'Referer': '9zqjx', 'User-Agent':'9zqjx'}
