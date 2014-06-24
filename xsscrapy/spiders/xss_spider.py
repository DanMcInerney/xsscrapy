from scrapy.contrib.linkextractors.sgml import SgmlLinkExtractor
from scrapy.contrib.spiders import CrawlSpider, Rule
from scrapy.selector import Selector
from scrapy.http import Request, FormRequest

from xsscrapy.items import Link
from loginform import fill_login_form

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

        self.login_user = kwargs.get('user')
        print self.login_user
        self.login_pass = kwargs.get('pw')
        print self.login_pass

#### Handle logging in if username and password are given as arguments ####
    def start_requests(self):
        if self.login_user and self.login_pass:
            yield Request(url=self.start_urls[0], callback=self.login)
        else:
            yield Request(url=self.start_urls[0]) # Take out the callback arg so crawler falls back to the rules' callback

    def login(self, response):
        args, url, method = fill_login_form(response.url, response.body, self.login_user, self.login_pass)
        return FormRequest(url, method=method, formdata=args, callback=self.confirm_login, dont_filter=True)

    def confirm_login(self, response):
        if self.login_user.lower() in response.body.lower():
            self.log('Successfully logged in')
            return Request(url=self.start_urls[0], dont_filter=True)
        else:
            self.log('FAILED to log in! (or at least cannot find the username on the post-login page which may be OK)')
            return Request(url=self.start_urls[0], dont_filter=True)
############################################################################

    def parse_url(self, response):
        url = response.url
        body = response.body
        #if self.login_user and self.login_pass:

        payloaded_urls = self.payloader.run(url)
        if payloaded_urls:
            return [Request(url, callback=self.find_xss_in_body) for url in payloaded_urls]
        return

    def find_xss_in_body(self, response):
        ''' Logic for finding possible XSS vulnerabilities '''

        item = Link()
        delim = '9zqjx'
        body = response.body
        url = response.url
        tester = '"\'><()=;/:'
        re_tester = '\"\'><\(\)=;/:'
        tester_list = list(tester)
        foundChars = []
        allFoundChars = []
        allBetweenDelims = '%s(.*?)%s' % (delim, delim)
        tester_matches = re.findall(re_tester, body)

        if len(tester_matches) > 0:
            print '-------------------- 100% vulnerable: '+url
            item['vuln_url'] = url+' -- '+tester_matches[0]
            return item

        delimed_matches = re.findall(allBetweenDelims, body)
        if len(delimed_matches) > 0:
            for m in delimed_matches:
                # Check for the special chars
                for c in tester_list:
                    if c in m:
                        foundChars.append(c)
                #print 'Found chars:', foundChars, url
                allFoundChars.append(foundChars)
                foundChars = []
            #print allFoundChars, url
            for chars in allFoundChars:
                if tester_list == chars:
                    print '-------------------- 100% vulnerable: '+url
                    item['vuln_url'] = url
                    return item
                elif set(['"', '<', '>', '=', ')', '(']).issubset(set(chars)):
                    item['vuln_url'] = url
                    return item
                #elif set([';', '(', ')']).issubset(set(chars)):
                #    print 'If this parameter is reflected in javascript, try payload: javascript:alert(1)', url

            allFoundChars = []

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
