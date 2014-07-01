from scrapy.contrib.linkextractors.sgml import SgmlLinkExtractor
from scrapy.contrib.spiders import CrawlSpider, Rule
from scrapy.selector import Selector
from scrapy.http import Request, FormRequest

from xsscrapy.items import URL
from loginform import fill_login_form

from urlparse import urlparse, parse_qsl
import lxml.html
import urllib
import re
import sys

'''
xss headers:
cookie
agent
data control
'''


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
        self.test_str = '9zqjx'

        self.login_user = kwargs.get('user')
        self.login_pass = kwargs.get('pw')

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
            self.log('Successfully logged in (or, at least, the username showed up in the response html)')
            return Request(url=self.start_urls[0], dont_filter=True)
        else:
            self.log('FAILED to log in! (or at least cannot find the username on the post-login page which may be OK)')
            return Request(url=self.start_urls[0], dont_filter=True)
    ############################################################################

    def parse_url(self, response):
        resp_url = response.url
        body = response.body
        payloaded_urls = None

        if '=' in resp_url:
            payloaded_urls = self.makeURLs(resp_url, self.test_str)

        if payloaded_urls:
            payloaded_reqs = [Request(url, callback=self.injection_finder, meta={'payload':self.test_str, 'orig_url':url}) for url in payloaded_urls] # Meta is the payload
            return payloaded_reqs
        return

    def makeURLs(self, url, payloads):
        ''' Add links with variables in them to the queue again but with XSS testing payloads '''
        if type(payloads) == str:
            payloads = [payloads]
        payloaded_urls = []
        params = self.getURLparams(url)
        moddedParams = self.change_params(params, payloads)
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

    def change_params(self, params, payloads):
        ''' Returns a list of complete parameters, each with 1 parameter changed to an XSS vector '''
        changedParams = []
        changedParam = False
        moddedParams = []
        allModdedParams = {}

        # Create a list of lists, each list will be the URL we will test
        # This preserves the order of the URL parameters and will also
        # test each parameter individually instead of all at once
        for payload in payloads:
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

    def injection_finder(self, response):
        ''' Check for injection locations in app '''
        body = response.body
        root = lxml.html.fromstring(body)
#        html = lxml.html.tostring(root, pretty_print=True)
        url = response.url
        payload = response.meta['payload']
        injections = []
        num_injections = 0
        quote_enclosure = self.single_or_double_quote(body)

        attr_xss = root.xpath("//@*[contains(., '%s')]" % payload)
        elem_attr = self.get_elem_attr(attr_xss)
        text_xss = root.xpath("//*[contains(text(), '%s')]" % payload)
        tags = self.get_text_xss_tags(text_xss)

        if elem_attr:
            num_injections = len(elem_attr)
        if tags:
            num_injections = num_injections + len(tags)

        if num_injections > 0:
            self.log('%d injection points in %s' % (num_injections, url))

            if tags:
                for t in tags:
                    line = t[0]
                    tag = t[1]
                    self.log('Found injection point between <%s> tags' % tag)
                    injections.append((line, 'tag', tag))
            if elem_attr:
                for ea in elem_attr:
                    line = ea[0]
                    tag = ea[1]
                    attr = ea[2]
                    attr_val = ea[3]
                    if attr == 'href' and payload == attr_val:
                        redir = True # sets the stage for a JaVASCrIPT:prompt(55) payload since the href value is the same as the payload
                    else:
                        redir = None
                    self.log('Found attribute injection point in <%s> tag\'s attribute "%s"' % (tag, attr))
                    injections.append((line, 'attr', tag, attr, redir))

            injections = sorted(injections)
            orig_url = response.meta['orig_url']
            xss_reqs = self.xss_req_maker(injections, orig_url, quote_enclosure)
            return xss_reqs

        ##################################

    def xss_req_maker(self, injections, orig_url, quote_enclosure):
        # If injection between <script> tags, check single+double quotes, semi-colon
        # if in href attr and value is identical to input, check JaVaScRIPt:prompt(44)
        # populated from http://www.w3schools.com/tags/ref_eventattributes.asp
        event_attributes = ['onafterprint', 'onbeforeprint', 'onbeforeunload', 'onerror',
                            'onhaschange', 'onload', 'onmessage', 'onoffline', 'ononline',
                            'onpagehide', 'onpageshow', 'onpopstate', 'onredo', 'onresize',
                            'onstorage', 'onundo', 'onunload', 'onblur', 'onchange',
                            'oncontextmenu', 'onfocus', 'onformchange', 'onforminput',
                            'oninput', 'oninvalid', 'onreset', 'onselect', 'onsubmit',
                            'onkeydown', 'onkeypress', 'onkeyup', 'onclick', 'ondblclick',
                            'ondrag', 'ondragend', 'ondragenter', 'ondragleave', 'ondragover',
                            'ondragstart', 'ondrop', 'onmousedown', 'onmousemove',
                            'onmouseout', 'onmouseover', 'onmouseup', 'onmousewheel',
                            'onscroll', 'onabort', 'oncanplay', 'oncanplaythrough',
                            'ondurationchange', 'onemptied', 'onended', 'onerror',
                            'onloadeddata', 'onloadedmetadata', 'onloadstart', 'onpause',
                            'onplay', 'onplaying', 'onprogress', 'onratechange',
                            'onreadystatechange', 'onseeked', 'onseeking', 'onstalled',
                            'onsuspend', 'ontimeupdate', 'onvolumechange', 'onwaiting']

        reqs = []
        tag_payload = '()=<>'
        attr_payload = quote_enclosure+tag_payload
        js_payload = '\'"(){}[]'
        redir_payload = 'JaVAscRIPT:prompt(99)'
        payloads = []

        # Big 3 XSSes: in a tag attribute, inbetween tags, and within embedded JS
        for i in injections:
            print i
            line = i[0]
            kind = i[1]
            tag = i[2]

            if kind == 'tag':

                # Test for embedded JS XSS
                if tag == 'script': # Make sure we're not doubling the JS-escaping payload
                    if js_payload not in payloads:
                        payloads.append(js_payload)

                # Test for normal between tag XSS (no quotes necessary)
                if tag_payload not in payloads and attr_payload not in payloads:
                    payloads.append(tag_payload)

            if kind == 'attr':
                attr = i[3]
                redir = i[4] # Just a check to see if there's a redirect/xss vuln possibility

                # Test for javascript-executing attribute-based XSS
                if attr in event_attributes:
                    if js_payload not in payloads:
                        payloads.append(js_payload)

                # Test for open redirect/XSS if user input is reflected in entirety in href attribute value
                elif attr == 'href':
                    if i[4] == True and redire_payload not in payloads: # the user input is the entire attribute value of attr href
                        payloads.append(redir_payload)

                # Test for normal attribute-based XSS (needs either ' or " to be unescaped depending on which char the value is wrapped in
                if attr_payload not in payloads:
                    # Check if tag payload is in payloads, if it is then just change it in place to include quotes to escape attribute text
                    if tag_payload not in payloads:
                        payloads.append(attr_payload)
                    else:
                        for idx, p in enumerate(payloads):
                            if tag_payload == p:
                                p = attr_payload
                                payloads[idx] = p

        # Add delimeter to payloads
        payloads = [(self.test_str+p+self.test_str, self.test_str+urllib.quote_plus(p)+self.test_str) for p in payloads]
        reqs = self.xssed_url_gen(orig_url, payloads, injections)
        #for r in reqs:
        #    print r

        return reqs

    def single_or_double_quote(self, body):
        ''' I feel like this function is poorly written. At least it seems reliable. '''
        quote = re.search('<a href=(.)', body)
        if quote == None:
            quote = re.search('<link href=(.)', body)

        try:
            quote = quote.group(1)
        except AttributeError:
            squote = re.findall('.=(\')', body)
            dquote = re.findall('.=(")', body)
            if len(squote) > len(dquote):
                quote = "'"
            else:
                quote = '"'
        return quote

    def xssed_url_gen(self, orig_url, payloads, injections):
        urls = [(orig_url.replace(self.test_str, i), p[0]) for p in payloads for i in p] # list of (url, unencoded payload)
        p_reqs = [Request(url[0], callback=self.xss_chars_finder, meta={'payload':url[1], 'injections':injections}, dont_filter=True) for url in urls] # url[0] = url   url[1] = unencoded payload
        return p_reqs

    def get_elem_attr(self, attr_xss):
        elem_attr = []
        if len(attr_xss) > 0:
            for x in attr_xss:
                for y in x.getparent().items():
                    if x == y[1]:
                        tag = x.getparent().tag
                        attr = y[0]
                        line = x.getparent().sourceline
                        attr_val = x
                        elem_attr.append((line, tag, attr, attr_val))
            return elem_attr

    def get_text_xss_tags(self, text_xss):
        text_xss_tags = []
        if len(text_xss) > 0:
            tags = []
            for x in text_xss:
                text_xss_tags.append((x.sourceline, x.tag))
            return text_xss_tags

    def xss_chars_finder(self, response):
        ''' Find which chars, if any, are filtered '''
        item = URL()

        all_found_chars = []
        found_chars = []
        body = response.body
        #root = fromstring(body)
        url = response.url
        injections = response.meta['injections']
        payload = response.meta['payload']
        no_delim_payload = payload.strip(self.test_str)
        chars_between_delims = '%s(.*?)%s' % (self.test_str, self.test_str)

        # Check the entire body for exact match
        #if no_delim_payload in body:
        #    #print '>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> 100% vulnerable: '+url
        #    item['high'] = 'No filtered XSS characters: '+url
        #    return item

        delimed_matches = re.findall(chars_between_delims, body)
        xss_num = len(delimed_matches)
        inj_num = len(injections)

        if xss_num != inj_num:
            err = ('%s\nMismatch between injection count and xss character injection count: %d vs %d' % (url, inj_num, xss_num))
            item['error'] = err
            return item

        inject_types = zip([i[1] for i in injections], delimed_matches)
        print inject_types

        if xss_num > 0:
            # Check for the special chars and append them to a master list of tuples, one tuple per injection point
            for m in delimed_matches:
                for c in no_delim_payload:
                    if c in m:
                        found_chars.append(c)
                all_found_chars.append(found_chars)
                found_chars = []

            all_found_chars = []


#        delimed_matches = re.findall(allBetweenDelims, body)
#        if len(delimed_matches) > 0:
#            for m in delimed_matches:
#                # Check for the special chars
#                for c in tester_list:
#                    if c in m:
#                        foundChars.append(c)
#                #print 'Found chars:', foundChars, url
#                allFoundChars.append(foundChars)
#                foundChars = []
#            #print allFoundChars, url
#            for chars in allFoundChars:
#                if tester_list == chars:
#                    print '-------------------- 100% vulnerable: '+url
#                    item['vuln_url'] = url
#                    return item
#                elif set(['"', '<', '>', '=', ')', '(']).issubset(set(chars)):
#                    item['vuln_url'] = url
#                    return item
#                #elif set([';', '(', ')']).issubset(set(chars)):
#                #    print 'If this parameter is reflected in javascript, try payload: javascript:alert(1)', url
#
#            allFoundChars = []
######################################3
        #if len(attr_xss) + len(text_xss) > 0:
        #    # If it's an XSS in an attribute then we add the ' and " chars to the payload since those are necessary to break out of the attr
        #    if elem_attr:
        #        xss_chars = '(\'")=<>' #"><svg/onload=alert(1)
        #        # encoded_chars = [hex, decimal, html, xss_chars]
        #        encoded_chars = [xss_chars]
        #    else:
        #        xss_chars = '()=<>' #<svg/onload=alert(1)>
        #        # encoded_chars = [hex, decimal, html, xss_chars]
        #        encoded_chars = [xss_chars]

        #    #for i in encoded_chars:

        #    xss_chars_payload = self.test_str+xss_chars+self.test_str

        #    urls = self.makeURLs(url, xss_chars_payload)
        #    xss_chars_reqs = [Request(url, callback=self.xss_chars_finder, meta={'payload':xss_chars_payload}) for url in urls] # Meta is the payload
        #    return xss_chars_reqs
####################################################3
 #           for i in all_found_chars:
 #               filtered_chars = list(set(list(payload) - set(i)))
 #               print filtered_chars
 #               item['vuln_url'] = url
 #               if '"' in payload or '"' in payload: # then it's an attribute or JS injection
 #                   if '"' in i and "'" in i:
 #                       item['high'] = 'Possible to break out of JS or attribute. Injected chars: '+''.join(i)
 #                   else: # only ' or " was found to be injected but not both
 #                       if '"' in i:
 #                           item['high'] = 'Possible to break out of attribute or JS if enclosed with " char. Injected chars: '+''.join(i)
 #                       if "'" in i:
 #                           item['high'] = 'Possible to break out of attribute or JS if enclosed with " char. Injected chars: '+''.join(i)
 #               else: # it's only a between tag injection




   #             matched_payload = []
   #             for fc in all_found_chars:
   #                 print 'found_chars:',fc
   #                 for c in fc:
   #                     if c in payload:
   #                         matched_payload.append(c)
   #             print 'matched:', matched_payload

