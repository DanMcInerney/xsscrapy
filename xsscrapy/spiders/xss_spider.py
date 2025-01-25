# -- coding: utf-8 --

import random
import string

from scrapy.http import Response
from scrapy.http.cookies import CookieJar
from scrapy.http.request.form import FormElement, InputElement, TextareaElement
from scrapy.linkextractors import LinkExtractor
from scrapy.spiders import CrawlSpider, Rule
from scrapy.http import FormRequest, Request
from xsscrapy.items import inj_resp
from xsscrapy.loginform import fill_login_form
from urllib.parse import (
    ParseResult, urlparse, parse_qsl, urljoin, urlunparse, urlencode, unquote
)
from lxml import html, etree


__author__ = 'Dan McInerney danhmcinerney@gmail.com'


class XSSspider(CrawlSpider):
    name = 'xsscrapy'
    handle_httpstatus_list = [x for x in range(600) if not (300 <= x < 400)]
    rules = (Rule(LinkExtractor(), callback='parse_resp', follow=True), )

    def __init__(self, *args, **kwargs):
        # run using: scrapy crawl xss_spider -a url='http://example.com'
        super(XSSspider, self).__init__(*args, **kwargs)
        self.start_urls = [kwargs.get('url')]
        hostname = urlparse(
            self.start_urls[0]).hostname if self.start_urls else None
        # With subdomains
        # adding [] around the value seems to allow it to crawl subdomain of value
        self.allowed_domains = [hostname] if hostname else []
        self.delim = '1zqj'
        # semi colon goes on end because sometimes it cuts stuff off like
        # gruyere or the second cookie delim
        self.test_str = '\'"(){}<x>:/'

        # Login details. Either user or cookie
        self.login_user = kwargs.get('user')
        self.login_pass = kwargs.get('pw')
        self.login_cookie_key = kwargs.get('cookie_key')
        self.login_cookie_value = kwargs.get('cookie_value')

        if self.login_user or (self.login_cookie_key and self.login_cookie_value):
            # Don't hit links with 'logout' in them since self.login_user or cookies exists
            self.rules = (Rule(LinkExtractor(deny=('logout')),
                          callback='parse_resp', follow=True), )

        if not self.login_pass and self.login_user:
            self.login_pass = input("Please enter the password: ")

        self.basic_auth = kwargs.get('basic')
        if self.basic_auth:
            self.http_user = self.login_user
            self.http_pass = self.login_pass

    def parse_start_url(self, response: Response):
        """Creates the XSS tester requests for the start URL and the request for robots.txt."""
        u = urlparse(response.url)
        self.base_url = f"{u.scheme}://{u.netloc}"

        robots_url = f"{self.base_url}/robots.txt"
        robot_req = Request(robots_url, callback=self.robot_parser)

        fourohfour_url = self.start_urls[0]+'/requestXaX404'
        fourohfour_req = Request(fourohfour_url, callback=self.parse_resp)

        reqs = self.parse_resp(response)
        reqs.append(robot_req)
        reqs.append(fourohfour_req)

        return reqs

    def start_requests(self):
        """Generates the initial requests with login details, basic auth, and cookies."""
        cookies = {
            self.login_cookie_key: self.login_cookie_value} if self.login_cookie_key and self.login_cookie_value else None
        if self.login_user and self.login_pass:
            if self.basic_auth == 'true':
                yield Request(url=self.start_urls[0], cookies=cookies, callback=(self.login if not cookies else None))
            else:
                yield Request(url=self.start_urls[0], cookies=cookies, callback=(self.login if not cookies else None))
        else:
            yield Request(url=self.start_urls[0], cookies=cookies)

    def login(self, response: Response):
        """Fill out the login form and return the request."""
        self.log('Logging in...')
        try:
            args, url, method = fill_login_form(
                response.url, response.body, self.login_user, self.login_pass
            )
            return FormRequest(
                url=url,
                method=method,
                formdata=args,
                callback=self.confirm_login,
                dont_filter=True
            )
        except Exception as e:
            self.log(f'Error logging in: {e}')
            return Request(url=self.start_urls[0], dont_filter=True)

    def confirm_login(self, response: Response):
        """Check that the username is present on the post-login page."""
        username: str = self.login_user.lower()
        if username in response.text.lower():
            self.log('Successfully logged in! Username found in the response HTML.')
        else:
            self.log(
                'Username not found in the response HTML, assuming login failed.')
        return Request(url=self.start_urls[0], dont_filter=True)

    def robot_parser(self, response: Response):
        """Parse the robots.txt file and create Requests for the disallowed domains."""
        disallowed_urls = set([])
        for line in response.text.splitlines():
            if 'disallow: ' in line.lower():
                try:
                    address = line.split()[1]
                except IndexError:
                    # In case Disallow: has no value after it
                    continue
                disallowed = self.base_url+address
                disallowed_urls.add(disallowed)
        reqs = [Request(u, callback=self.parse_resp)
                for u in disallowed_urls if u != self.base_url]
        for r in reqs:
            self.log(f'Added robots.txt disallowed URL to our queue: {r.url}')
        return reqs

    def parse_resp(self, response: Response):
        """
        The main response parsing function, called on every response from a new URL
        Checks for XSS in headers and url
        """
        orig_url: str = response.url
        body: bytes = response.body
        parsed_url: ParseResult = urlparse(orig_url)
        url_params = parse_qsl(parsed_url.query, keep_blank_values=True)

        try:
            doc: html.HtmlElement = html.fromstring(body, base_url=orig_url)
        except (etree.ParserError, etree.XMLSyntaxError) as e:
            self.log(f'{type(e).__name__} from lxml on {orig_url}')
            return []

        reqs: list[Request] = []
        reqs.extend(self.make_iframe_reqs(doc, orig_url))

        test_headers = ['Referer']
        if 'UA' in response.meta and response.meta['UA'] in response.text:
            test_headers.append('User-Agent')
        reqs.extend(self.make_header_reqs(
            orig_url, self.test_str, test_headers))

        reqs.extend(self.make_cookie_reqs(orig_url, self.test_str, 'cookie'))

        forms: list[FormElement] = doc.xpath('//form')
        if forms:
            reqs.extend(self.make_form_reqs(orig_url, forms, self.test_str))

        payloaded_urls = self.make_urls(orig_url, parsed_url, url_params)
        if payloaded_urls:
            reqs.extend(self.make_url_reqs(orig_url, payloaded_urls))

        # Add the original untampered response to each request for use by sqli_check()
        for r in reqs:
            r.meta['orig_body'] = response.text

        return reqs

    def url_valid(self, url, orig_url: str):
        """
        Ensure the form URL is valid. If the form's action URL is missing or lacks a scheme,
        we attempt to construct a valid URL using the original page's URL (orig_url).
        """
        if not url:
            self.log("Form action URL is missing")
            return

        # Sometimes lxml doesn't read the form.action right
        if '://' not in url:
            self.log(
                "Form URL contains no scheme, attempting to construct a valid form submission URL."
            )
            # Use the original URL's scheme and domain to construct a full URL
            # Assuming this returns (domain, scheme)
            proc_url = self.url_processor(orig_url)
            url = proc_url[1] + proc_url[0] + url

        return url

    def make_iframe_reqs(self, doc: html.HtmlElement, orig_url: str):
        """
        Grab the <iframe src=...> attribute and add those URLs to the
        queue should they be within the start_url domain
        """
        iframe_reqs = []
        all_frames = doc.xpath('//iframe/@src') + doc.xpath('//frame/@src')

        for src in all_frames:
            src = src.strip() if isinstance(src, str) else None

            if '://' in src:
                # Absolute URL
                if self.base_url in src:
                    url = src
                    iframe_reqs.append(Request(src))
            else:
                # Relative URL
                url = urljoin(orig_url, src)
                iframe_reqs.append(Request(url))

        return iframe_reqs

    def make_form_reqs(self, orig_url: str, forms: list[FormElement], payload: str):
        """Payload each form input in each input's own request"""
        reqs = []
        payload = self.make_payload()

        for form in forms:
            if not form.inputs:
                continue

            method = form.method
            form_url = form.action or form.base_url
            url = self.url_valid(form_url, orig_url)

            if url and method:
                reqs.extend(self.create_form_request(
                    form, url, orig_url, payload))

        return reqs

    def create_form_request(self, form: FormElement, url: str, orig_url: str, payload: str):
        """Create a FormRequest for each form input."""
        reqs = []

        for input_element in form.inputs:
            if not isinstance(input_element, (InputElement, TextareaElement)):
                continue
            if isinstance(input_element, InputElement):
                # Don't change values for the below types because they
                # won't be strings and lxml will complain
                if input_element.type in ['checkbox', 'radio', 'submit']:
                    continue

            orig_val = form.fields.get(input_element.name, '')

            try:
                form.fields[input_element.name] = payload
            except ValueError as e:
                self.log(
                    f'Error while setting payload for {input_element.name}: {str(e)}')
                continue

            xss_param = input_element.name
            values = form.form_values()

            req = FormRequest(
                url,
                formdata=values,
                method=form.method,
                meta=self.create_meta(orig_url, payload, xss_param, url),
                dont_filter=True,
                callback=self.xss_chars_finder
            )
            reqs.append(req)

            # Reset the input value to its original state
            try:
                form.fields[input_element.name] = orig_val
            except ValueError as e:
                self.log(
                    f'Error while resetting {input_element.name}: {str(e)}')
                continue

        return reqs

    def create_meta(self, orig_url: str, payload: str, xss_param: str, url: str):
        """Create meta information for the request."""
        return {
            'payload': payload,
            'xss_param': xss_param,
            'orig_url': orig_url,
            'xss_place': 'form',
            'POST_to': url,
            'dont_redirect': True,
            'handle_httpstatus_list': range(300, 309),
            'delim': payload[:len(self.delim) + 2]
        }

    def make_cookie_reqs(self, url: str, payload: str, xss_param: str):
        """Generate payloaded cookie header requests"""
        payload = self.make_payload()
        reqs = [Request(url,
                        meta={'xss_place': 'header',
                              'cookiejar': CookieJar(),
                              'xss_param': xss_param,
                              'orig_url': url,
                              'payload': payload,
                              'dont_redirect': True,
                              'handle_httpstatus_list': range(300, 309),
                              'delim': payload[:len(self.delim)+2]},
                        cookies={'userinput': payload},
                        callback=self.xss_chars_finder,
                        dont_filter=True)]
        return reqs

    def make_urls(self, orig_url: str, parsed_url: ParseResult, url_params):
        """Create the URL parameter payloaded URLs"""
        payloaded_urls = []

        # Create 1 URL per payloaded param
        new_query_strings = self.get_single_payload_queries(url_params)
        if new_query_strings:
            # Payload the parameters
            for query in new_query_strings:
                query_str = query[0]
                params = query[1]
                payload = query[2]
                # scheme       #netlo         #path          #params        #query (url params) #fragment
                payloaded_url = urlunparse(
                    (parsed_url[0], parsed_url[1], parsed_url[2], parsed_url[3], query_str, parsed_url[5]))
                payloaded_url = unquote(payloaded_url)
                payloaded_urls.append((payloaded_url, params, payload))

            payloaded_url_path = self.payload_url_path(parsed_url)
            payloaded_urls.append(payloaded_url_path)
        else:
            payloaded_end_of_url = self.payload_end_of_url(orig_url)
            payloaded_urls.append(payloaded_end_of_url)

        return payloaded_urls

    def payload_url_path(self, parsed_url):
        """
        Payload the URL path like:
        http://example.com/page1.php?x=1&y=2 -->
        http://example.com/page1.php/FUZZ/?x=1&y=2
        """
        # Remove / so that it doesn't think it's 2 folders in the fuzz chars
        payload = self.make_payload().replace('/', '')
        path = parsed_url[2]
        if path.endswith('/'):
            path = f"{path}{payload}/"
        else:
            path = f"{path}/{payload}/"
            # scheme, netloc, path, params, query (url params), fragment
        payloaded_url = urlunparse(
            (parsed_url[0], parsed_url[1], path, parsed_url[3], parsed_url[4], parsed_url[5]))
        payloaded_url = unquote(payloaded_url)
        payloaded_data = (payloaded_url, 'URL path', payload)

        return payloaded_data

    def get_single_payload_queries(self, url_params):
        """
        Make a list of lists of tuples where each secondary list has 1 payloaded
        param and the rest are original value
        """
        new_payloaded_params = []
        changed_params = []
        modified = False
        # Create a list of lists where num of lists = len(params)
        for _ in range(0, len(url_params)):
            single_url_params = []

            # Make the payload
            payload = self.make_payload()

            for p in url_params:
                param, _ = p

                # if param has not been modified and we haven't changed a parameter for this loop
                if param not in changed_params and modified == False:
                    # Do we need the original value there? Might be helpful sometimes but think about testing for <frame src="FUZZCHARS">
                    # versus <frame src="http://something.com/FUZZCHARS"> and the xss payload javascript:alert(1)
                    new_param_val = (param, payload)
                    # new_param_val = (param, value+payload)
                    single_url_params.append(new_param_val)
                    changed_params.append(param)
                    modified = param
                else:
                    single_url_params.append(p)

            # Add the modified, urlencoded params to the master list
            new_payloaded_params.append(
                (urlencode(single_url_params), modified, payload))
            # Reset the changed parameter tracker
            modified = False

        return new_payloaded_params

    def make_payload(self):
        """Make the payload with a unique delim"""
        two_rand_letters = ''.join(random.choices(string.ascii_lowercase, k=2))
        delim_str = f"{self.delim}{two_rand_letters}"
        payload = delim_str + self.test_str + delim_str + ';9'
        return payload

    def payload_end_of_url(self, url: str):
        """Payload the end of the URL to catch some DOM(?) and other reflected XSSes"""
        payload = self.make_payload().replace('/', '')
        # Make URL test and delim strings unique
        if url[-1] == '/':
            payloaded_url = f"{url}{payload}"
        else:
            payloaded_url = f"{url}/{payload}"

        return (payloaded_url, 'end of url', payload)

    def payload_url_vars(self, url: str, payload: str):
        """Payload the URL variables"""
        payloaded_urls = []
        params = self.getURLparams(url)
        modded_params = self.change_params(params, payload)
        netloc, protocol, doc_domain, path = self.url_processor(url)
        if netloc and protocol and path:
            for payload in modded_params:
                for params in modded_params[payload]:
                    # doseq maps the params back together
                    joinedParams = urlencode(params, doseq=1)
                    newURL = unquote(protocol+netloc+path+'?'+joinedParams)

                    # Prevent nonpayloaded URLs
                    if self.test_str not in newURL:
                        continue

                    for p in params:
                        if payload in p[1]:
                            changed_value = p[0]

                    payloaded_urls.append((newURL, changed_value, payload))

        # Payload the path, like: example.com/page1.php?param=val becomes example.com/page1.php/FUZZCHARS/?param=val
        payloaded_urls.append(self.payload_path(url))

        return payloaded_urls

#    def payload_path(self, url):
#        ''' Payload the path, like: example.com/page1.php?param=val becomes example.com/page1.php/FUZZCHARS/?param=val '''
#        parsed = urlparse(url)

    def getURLparams(self, url: str):
        """Parse out the URL parameters"""
        parsedUrl: ParseResult = urlparse(url)
        fullParams = parsedUrl.query
        # parse_qsl rather than parse_ps in order to preserve order
        params = parse_qsl(fullParams, keep_blank_values=True)
        return params

    def change_params(self, params, payload):
        """Returns a list of complete parameters, each with 1 parameter changed to an XSS vector"""
        changed_params = []
        changed_param = False
        modded_params = []
        all_modded_params = {}

        # Create a list of lists, each list will be the URL we will test
        # This preserves the order of the URL parameters and will also
        # test each parameter individually instead of all at once
        all_modded_params[payload] = []
        for x in range(0, len(params)):
            for p in params:
                param = p[0]
                value = p[1]
                # If a parameter has not been modified yet
                if param not in changed_params and changed_param == False:
                    changed_params.append(param)
                    p = (param, value+payload)
                    modded_params.append(p)
                    changed_param = param
                else:
                    modded_params.append(p)

            # Reset so we can step through again and change a diff param
            # allModdedParams[payload].append(moddedParams)
            all_modded_params[payload].append(modded_params)

            changed_param = False
            modded_params = []

        # Reset the list of changed params each time a new payload is attempted
        # changedParams = []

        return all_modded_params

    def url_processor(self, url: str):
        """Get the url domain, protocol, and netloc using urlparse"""
        try:
            parsed_url: ParseResult = urlparse(url)
            path = parsed_url.path
            protocol = f"{parsed_url.scheme}://"
            hostname = parsed_url.hostname
            netloc = parsed_url.netloc
            doc_domain = '.'.join(hostname.split('.')[-2:])
        except:
            self.log(f"Error parsing URL: {url}")
            return

        return (netloc, protocol, doc_domain, path)

    def make_url_reqs(self, orig_url, payloaded_urls):
        """Make the URL requests with the payload"""

        reqs = [Request(url[0],
                        meta={'xss_place': 'url',
                              'xss_param': url[1],
                              'orig_url': orig_url,
                              'payload': url[2],
                              'dont_redirect': True,
                              'handle_httpstatus_list': range(300, 309),
                              'delim': url[2][:len(self.delim)+2]},
                        callback=self.xss_chars_finder)
                for url in payloaded_urls]  # Meta is the payload

        return reqs

    def make_header_reqs(self, url, payload, inj_headers):
        """Generate header requests with the payload"""
        payload = self.make_payload()

        reqs = [Request(url,
                        headers={inj_header: payload},
                        meta={'xss_place': 'header',
                              'xss_param': inj_header,
                              'orig_url': url,
                              'payload': payload,
                              'delim': payload[:len(self.delim)+2],
                              'dont_redirect': True,
                              'handle_httpstatus_list': range(300, 309),
                              'UA': self.get_user_agent(inj_header, payload)},
                        dont_filter=True,
                        callback=self.xss_chars_finder)
                for inj_header in inj_headers]

        return reqs

    def get_user_agent(self, header, payload):
        """Return the User-Agent header with the payload"""
        if header == 'User-Agent':
            return payload
        else:
            return ''

    def xss_chars_finder(self, response):
        """Find which chars, if any, are filtered"""
        item = inj_resp()
        item['resp'] = response
        return item
