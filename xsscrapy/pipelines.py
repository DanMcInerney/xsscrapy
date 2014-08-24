# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: http://doc.scrapy.org/en/latest/topics/item-pipeline.html
from scrapy.exceptions import DropItem
import HTMLParser
from xsscrapy.items import vuln#, inj_resp
import re

class XSSCharFinder(object):
    def __init__(self):
        self.test_str = '9zqjx'
        self.js_pld = '\'"(){}[];'
        self.url_param_xss_items = []

    def process_item(self, item, spider):
        response = item['resp']
        item = vuln()

        xss_type = response.meta['type']
        orig_url = response.meta['orig_url']
        injections = response.meta['injections']
        quote_enclosure = response.meta['quote']
        inj_point = response.meta['inj_point']
        resp_url = response.url
        body = response.body
        # Regex: ( ) mean group 1 is within the parens, . means any char,
        # {1,50} means match any char 1 to 50 times
        #chars_between_delims = '%s(.{1,50}?)%s' % (self.test_str, self.test_str)
        chars_between_delims = '%s(.{0,50}?)%s' % (self.test_str, self.test_str)
        inj_num = len(injections)
        mismatch = False
        if xss_type == 'form':
            POST_to = response.meta['POST_to']
        else:
            POST_to = None
        orig_payload = response.meta['payload'].strip(self.test_str) # xss char payload
        escaped_payload = self.unescape_payload(orig_payload)

        break_tag_chars = set(['>', '<', '(', ')'])
        break_attr_chars = set([quote_enclosure, '(', ')'])
        break_js_chars = set(['"', "'", '(', ')'])

        matches = re.findall(chars_between_delims, body)
        if matches:
            xss_num = len(matches)

            if xss_num != inj_num:
                err = ('Mismatch between harmless injection count and payloaded injection count: %d vs %d, increased chance of false positive' % (inj_num, xss_num))
                item['error'] = err

            for idx, match in enumerate(matches):
                unfiltered_chars = self.get_unfiltered_chars(match, escaped_payload)
                if unfiltered_chars:
                    try:
                        line, tag, attr, attr_val = spider.parse_injections(injections[idx])
                    except IndexError:
                        mismatch = True
                        # Mismatch in num of test injections and num of payloads found
                        line, tag, attr, attr_val = 'Unknown', 'Unknown', None, None

                    joined_chars = ''.join(unfiltered_chars)
                    chars = set(joined_chars)
                    line_html = self.get_inj_line(body, match)

                    ###### XSS RULES ########

                    # If there's more XSS matches than harmless injections, we still want to check for the most dangerous characters
                    # May see some false positives here, but better than false negatives
                    if mismatch == True:
                        if '>' in escaped_payload and '<' in escaped_payload:
                            if '<' in joined_chars and '>' in joined_chars:
                                item = self.make_item(joined_chars, xss_type, orig_payload, tag, orig_url, inj_point, line_html, POST_to, item)
                                item = self.url_item_filtering(item, spider)
                                return item

                    # Redirect
                    if 'javascript:prompt(99)' == joined_chars.lower(): # redir
                        item = self.make_item(joined_chars, xss_type, orig_payload, tag, orig_url, inj_point, line_html, POST_to, item)
                        item = self.url_item_filtering(item, spider)
                        return item

                    # JS breakout
                    if self.js_pld == escaped_payload: #js chars
                        if break_js_chars.issubset(chars):
                            item = self.make_item(joined_chars, xss_type, orig_payload, tag, orig_url, inj_point, line_html, POST_to, item)
                            item = self.url_item_filtering(item, spider)
                            return item

                    # Attribute breakout
                    if attr:
                        if quote_enclosure in escaped_payload:
                            if break_attr_chars.issubset(chars):
                                item = self.make_item(joined_chars, xss_type, orig_payload, tag, orig_url, inj_point, line_html, POST_to, item)
                                item = self.url_item_filtering(item, spider)
                                return item

                    # Tag breakout
                    else:
                        if '<' and '>' in escaped_payload:
                            if break_tag_chars.issubset(chars):
                                item = self.make_item(joined_chars, xss_type, orig_payload, tag, orig_url, inj_point, line_html, POST_to, item)
                                item = self.url_item_filtering(item, spider)
                                return item

        # Check the entire body for exact match
        # Escape out all the special regex characters to search for the payload in the html body
        re_payload = escaped_payload.replace('(', '\(').replace(')', '\)').replace('"', '\\"').replace("'", "\\'")
        re_payload = re_payload.replace('{', '\{').replace('}', '\}').replace(']', '\]').replace('[', '\[')
        re_payload = '.{1}?'+re_payload
        full_matches = re.findall(re_payload, body)
        for f in full_matches:
            unescaped_match = ''.join(self.get_unfiltered_chars(f, escaped_payload))
            if unescaped_match == escaped_payload:
                #if '\\' == unescaped_match[0]:
                #    continue
                item['error'] = 'Response passed injection point specific search without success, checked for exact payload match in body (higher chance of false positive here)'
                item['line'] = self.get_inj_line(body, f)
                item['xss_payload'] = orig_payload
                item['unfiltered'] = escaped_payload
                item['inj_point'] = inj_point
                item['xss_type'] = xss_type
                item['url'] = orig_url
                if POST_to:
                    item['POST_to'] = POST_to
                return item

        # In case it slips by all of the filters, then we move on
        raise DropItem('No XSS vulns in %s. Tested: type = %s, injection point = %s' % (resp_url, xss_type, inj_point))

    def unescape_payload(self, payload):
        ''' Unescape the various payload encodings (html and url encodings)'''
        if '%' in payload:
            payload = urllib.unquote_plus(payload)
            #if '%' in payload: # in case we ever add double url encoding like %2522 for dub quote
            #    payload = urllib.unquote_plus(payload)
        # only html-encoded payloads will have & in them
        payload = HTMLParser.HTMLParser().unescape(payload)

        return payload

    def get_inj_line(self, body, payload):
        lines = []
        html_lines = body.splitlines()
        for idx, line in enumerate(html_lines):
            line = line.strip()
            if payload in line:
                num_txt = (idx, line)
                lines.append(num_txt)

        if len(lines) > 0:
            return lines

    def get_unfiltered_chars(self, match, escaped_payload):
        ''' Check for the special chars and append them to a master list of tuples, one tuple per injection point '''
        unfiltered_chars = []

        # Make sure js payloads remove escaped ' and "
        escaped_chars = re.findall(r'\\(.)', match)
        for escaped_char in escaped_chars:
            if escaped_char not in ['x', 'u']: # x and u for hex and unicode like \x43, \u0022
                match = match.replace(escaped_char, '')

        for c in escaped_payload:
            if c in match:
                unfiltered_chars.append(c)

        if len(unfiltered_chars) > 0:
            return unfiltered_chars

    def make_item(self, joined_chars, xss_type, orig_payload, tag, orig_url, inj_point, line, POST_to, item):
        ''' Create the vulnerable item '''

        item['line'] = line
        item['xss_payload'] = orig_payload
        item['unfiltered'] = joined_chars
        item['inj_point'] = inj_point
        item['xss_type'] = xss_type
        item['inj_tag'] = tag
        item['url'] = orig_url
        if POST_to:
            item['POST_to'] = POST_to
        return item

    def url_item_filtering(self, item, spider):
        ''' Make sure we're not just repeating the same URL XSS over and over '''

        if item['xss_type'] == 'url':

            if len(self.url_param_xss_items) > 0:

                for i in self.url_param_xss_items:
                    # If the injection param, the url up until the injected param and the payload
                    # are all the same as a previous item, then don't bother creating the item

                    # Match tags where injection point was found
                    if item['inj_point'] == i['inj_point']:

                        # Match the URL up until the params
                        if item['url'].split('?', 1)[0] == i['url'].split('?', 1)[0]:

                            # Match the payload
                            if item['xss_payload'] == i['xss_payload']:

                                # Match the unfiltered characters
                                if item['unfiltered'] == i['unfiltered']:

                                    raise DropItem('Duplicate item found: %s' % item['url'])


            self.url_param_xss_items.append(item)

        self.write_to_file(item, spider)

        return item

    def write_to_file(self, item, spider):
        with open('formatted-vulns.txt', 'a+') as f:
            f.write('\n')

            f.write('URL: '+item['url']+'\n')
            spider.log('    URL: '+item['url'], level='INFO')

            if 'POST_to' in item:
                f.write('POST url: '+item['POST_to']+'\n')
                spider.log('    POST url: '+item['POST_to'], level='INFO')

            f.write('Unfiltered: '+item['unfiltered']+'\n')
            spider.log('    Unfiltered: '+item['unfiltered'], level='INFO')

            f.write('Payload: '+item['xss_payload']+'\n')
            spider.log('    Payload: '+item['xss_payload'], level='INFO')

            f.write('Type: '+item['xss_type']+'\n')
            spider.log('    Type: '+item['xss_type'], level='INFO')

            f.write('Injection point: '+item['inj_point']+'\n')
            spider.log('    Injection point: '+item['inj_point'], level='INFO')

            for line in item['line']:
                f.write('Line: '+line[1]+'\n')
                spider.log('    Line: '+line[1], level='INFO')

            if 'error' in item:
                f.write('Error: '+item['error']+'\n')
                spider.log('    Error: '+item['error'], level='INFO')

