from scrapy.contrib.linkextractors.sgml import SgmlLinkExtractor
from scrapy.contrib.spiders import CrawlSpider, Rule
from scrapy.selector import Selector
from scrapy.http import Request

from xsscrapy.items import Link

from urlparse import urlparse, parse_qsl
import urllib
import re


class XSSspider(CrawlSpider):
    name = 'xss_spider'
    #allowed_domains = ['coin.co']
    #start_urls = ['http://coin.co']

    rules = (Rule(SgmlLinkExtractor(), callback='parse_url', follow=True), )

    def __init__(self, *args, **kwargs):
        # run using: scrapy crawl xss_spider -a url='http://kadira.com'
        super(XSSspider, self).__init__(*args, **kwargs)
        self.start_urls = [kwargs.get('url')]
        hostname = urlparse(self.start_urls[0]).hostname
        self.allowed_domains = ['.'.join(hostname.split('.')[-2:])] # adding [] around the value seems to allow it to crawl subdomain of value
        self.payloader = xss_payloader()

    def parse_url(self, response):
        item = Link()
        item['url'] = response.url
        payloaded_urls = self.payloader.run(item['url'])
        if payloaded_urls:
            return [Request(url, callback=self.find_xss_in_body) for url in payloaded_urls]

        #item['body'] = response.body
        return item

    def find_xss_in_body(self, response):
        delim = '9zqjx'
        body = response.body
        url = response.url
        tester = '"\'><()=;/:'
        if tester in body:
            print '------------------------- 100% vulnerable:', url

        allBetweenDelims = '%s(.*?)%s' % (delim, delim)
        matches = re.findall(allBetweenDelims, body)
        if len(matches) > 0:
            pass


class xss_payloader:
    ''' Find urls with parameters then return a list of urls with 1 xss payload per param '''

    def __init__(self):
        self.xssDelim = '9zqjx' # zqjx has the least amount of google search results I can find for 4 letter combo (47.2K)
        self.payloadTests = [self.xssDelim+'"\'><()=;/:'+self.xssDelim, # Normal check
                             self.xssDelim+'%22%27%3E%3C%28%29%3D%3B%2F%3A'+self.xssDelim, # Hex encoded
                             self.xssDelim+'&#34&#39&#62&#60&#40&#41&#61&#59&#47&#58'+self.xssDelim] # HTML encoded without semicolons

    def run(self, url):
        if '=' in url:
            payloaded_urls = self.checkForURLparams(url)
            return payloaded_urls

    def checkForURLparams(self, url):
        ''' Add links with variables in them to the queue again but with XSS testing payloads '''
        payloaded_urls = []
        params = self.getURLparams(url)
        moddedParams = self.change_params(params)
        hostname, protocol, root_domain, path = self.url_processor(url)
        if hostname and protocol and path:
            for payload in moddedParams:
                for params in moddedParams[payload]:
                    joinedParams = urllib.urlencode(params, doseq=1) # doseq maps the params back together
                    newURL = urllib.unquote(protocol+hostname+path+'?'+joinedParams)
                    payloaded_urls.append(newURL)
        return payloaded_urls

    def getURLparams(self, url):
        ''' Parse out the URL parameters '''
        parsedUrl = urlparse(url)
        fullParams = parsedUrl.query
        params = parse_qsl(fullParams) #parse_qsl rather than parse_ps in order to preserve order
        return params

    def change_params(self, params):
        ''' Returns a list of complete parameters, each with 1 parameter changed to an XSS vector '''
        changedParams = []
        changedParam = False
        moddedParams = []
        allModdedParams = {}

        # Create a list of lists, each list will be the URL we will test
        # This preserves the order of the URL parameters and will also
        # test each parameter individually instead of all at once
        for payload in self.payloadTests:
            allModdedParams[payload] = []
            for x in xrange(0, len(params)):
                for p in params:
                    param = p[0]
                    value = p[1]
                    # If a parameter has not been modified yet
                    if param not in changedParams and changedParam == False:
                        newValue = payload
                        changedParams.append(param)
                        p = (param, newValue)
                        moddedParams.append(p)
                        changedParam = True
                    else:
                        moddedParams.append(p)

                # Reset so we can step through again and change a diff param
                allModdedParams[payload].append(moddedParams)

                changedParam = False
                moddedParams = []

            # Reset the list of changed params each time a new payload is attempted
            changedParams = []

        return allModdedParams

    def url_processor(self, url):
        ''' Get the url domain, protocol, and hostname using urlparse '''
        try:
            parsed_url = urlparse(url)
            # Get the path
            path = parsed_url.path
            # Get the protocol
            protocol = parsed_url.scheme+'://'
            # Get the hostname (includes subdomains)
            hostname = parsed_url.hostname
            # Get root domain
            root_domain = '.'.join(hostname.split('.')[-2:])
        except:
            print '[-] Could not parse url:', url
            return

        return (hostname, protocol, root_domain, path)
