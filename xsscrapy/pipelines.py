# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: http://doc.scrapy.org/en/latest/topics/item-pipeline.html
from scrapy.exceptions import DropItem
import HTMLParser
from xsscrapy.items import vuln#, inj_resp
import re
import lxml.html
import lxml.etree
from IPython import embed

class XSSCharFinder(object):
    def __init__(self):
        self.redir_pld = 'JaVAscRIPT:prompt(99)'
        self.test_str = '\'"(){}<x>:'
        self.url_param_xss_items = []

    def process_item(self, item, spider):
        response = item['resp']
        meta = response.meta
        item = vuln()

        payload = meta['payload']
        delim = meta['delim']
        resp_url = response.url
        body = response.body
        mismatch = False
        orig_payload = payload.replace(delim, '').replace(';9', '') # xss char payload
        # Regex: ( ) mean group 1 is within the parens, . means any char,
        # {1,50} means match any char 0 to 72 times, 72 chosen because double URL encoding
        # ? makes the search nongreedy so it stops after hitting its limits
        full_match = '%s.*?%s' % (delim, delim)
        # matches with semicolon which sometimes cuts results off
        sc_full_match = '%s.*?%s;9' % (delim, delim)
        chars_between_delims = '%s(.*?)%s' % (delim, delim)

        re_matches = sorted([(m.start(), m.group()) for m in re.finditer(full_match, body)])
        if re_matches:
            scolon_matches = sorted([(m.start(), m.group()) for m in re.finditer(sc_full_match, body)])
            lxml_match_data = self.get_lxml_matches(full_match, body, resp_url, delim)
            if lxml_match_data:
                if len(re_matches) != len(lxml_match_data):
                    spider.log('Mismatch in lxml parsed injections and regex parsed injections. Higher chance of false positive for %s' % resp_url)
                    mismatch = True

                inj_data = self.combine_inj_data(lxml_match_data, re_matches, scolon_matches, delim)
                for i in inj_data:
                    ########## XSS LOGIC #############
                    item = self.xss_logic(i, meta, resp_url, body)
                    if item:
                        if item['xss_place'] == 'url':
                            item = self.url_item_filtering(item, spider)
                        if mismatch:
                            item['error'] = 'Mismatch: html parsed vs regex parsed injections, %d vs %d. Higher chance of false positive' % (len(injections), len(full_matches))
                        self.write_to_file(item, spider)
                        return item

        # Catch all test payload chars no delims
        # Catches DB errors
        #pl_lines_found = self.payloaded_lines(body, orig_payload)
        #if pl_lines_found:
        #    print '\n\n\n      LAST RESORT\n     %s %s %s \n\n\n' % (resp_url, meta['xss_place'], meta['xss_param'])
        #    return self.make_item(meta, resp_url, pl_lines_found, orig_payload)
        raise DropItem('No XSS vulns in %s. type = %s, %s, %s'% (resp_url, meta['xss_place'], meta['xss_param'], meta['payload']))

    def xss_logic(self, injection, meta, resp_url, body):
        ''' XSS logic. Returns None if vulnerability not found 
        The breakout_chars var is a list(set()). This ensure we can
        test for breakout given OR statements, like " or ; to breakout'''

        offset, payload, unfiltered, sourceline, tag, attr, attr_val = injection
        body = body.lower()

######## CHANGE FROM line TO lines HAPPENS HERE
        if unfiltered:
            breakout_chars, lines = self.get_breakout_chars(injection, body)
            if breakout_chars:
                for chars in breakout_chars:
                    if chars.issubset(set(unfiltered)):
                        return self.make_item(meta, resp_url, lines, unfiltered)

            # Check for completely unfiltered injection
            #if unfiltered.replace(';', '') == self.test_str:
            #    return self.make_item(meta, resp_url, lines, unfiltered)

    def get_breakout_chars(self, injection, body):
        ''' Returns either None if no breakout chars were found
        or a list of sets of potential breakout characters '''

        match_offset = injection[0]
        payload = injection[1]
        unfiltered = injection[2]
        tag = injection[4]
        attr = injection[5]
        attr_val = injection[6]
        delim = payload[:7]
        split_body = body[:match_offset]
        payload_from_body = delim + body[match_offset:].split(delim)[1] + delim #[0] is '', [1] is payload chars
        if ';' in unfiltered:
            payload_from_body = payload_from_body + ';9'

        # Do comments first since they're just 1 char
        # We custom set the comment tag in comm_inj to !--
        # so that we can split the line at <!-- rather than
        # whatever tag is closest to the comment
        if tag == '!--':
            breakout_chars, line = self.comment_breakout(split_body, tag, payload_from_body)

        # Then check attribute breakouts
        elif attr:
            breakout_chars, line = self.attr_breakout(split_body, tag, attr, attr_val, delim, payload, payload_from_body)

        # Finally check between tag breakout
        else:
            breakout_chars, line = self.tag_breakout(split_body, tag, payload, payload_from_body)

        if breakout_chars:
            return breakout_chars, line
        else:
            return None, None

    def tag_breakout(self, split_body, tag, payload, payload_from_body):
        breakout_chars = []
        split_delim = '<'+tag
        sub = 'INJECTION'
        line = split_delim + split_body.split(split_delim)[-1]
        line = re.sub(payload, sub, line)
        line = line.replace('\\"', '').replace("\\'", "")

        # Look for javascript breakouts
        if tag == 'script':
            # Get rid of javascript escaped quotes
            dquote_open, squote_open = self.get_quote_context(line)
            if dquote_open:
                breakout_chars.append(set(['"']))
            if squote_open:
                breakout_chars.append(set(["'"]))
            # If neither double nor single quotes are open at injection point, we just need a ;
            if not dquote_open and not squote_open:
                breakout_chars.append(set([';']))
                #breakout_chars.append(set(['<', '>']))

        # Everything that's not a script tag
        else:
            breakout_chars.append(set(['<','>']))

        return breakout_chars, line + payload_from_body

    def attr_breakout(self, split_body, tag, attr, attr_val, delim, payload, payload_from_body):
        breakout_chars = []
        #Find the nearest <tag
        split_delim = '<'+tag
        sub = 'INJECTION'
        line = split_delim + split_body.split(split_delim)[-1]
        line = re.sub(payload, sub, line)
        # Get rid of javascript escaped quotes
        line = line.replace('\\"', '').replace("\\'", "")

        # javascript:alert(1) vulns
        # also attr_val[index] because it might include ;9
        if attr_val[:len(delim+'subbed')] == delim+'subbed':
            if tag == 'a' and attr == 'href':
                # Only need : ( and ) to use javascript:prompt(4) redir payload
                breakout_chars.append(set([':', ')', '(']))
            # Inject the frame or script source file
            elif tag in ['script', 'frame', 'iframe']:
                if attr == 'src':
                    breakout_chars.append(set([':', ')', '(']))

        # Check if quotes even exist in the line
        if '"' in line or "'" in line:
            line = line.replace('\\"', '').replace("\\'", "")

            dquote_open, squote_open = self.get_quote_context(line)
            if dquote_open:
                breakout_chars.append(set(['"']))
            if squote_open:
                breakout_chars.append(set(["'"]))

            # Check for JS attributes
            if attr in self.event_attributes():
                # Scared this is too lenient. Possible source of false positives?
                if dquote_open and not squote_open:
                    breakout_chars.append(set([';']))
                elif squote_open and not dquote_open:
                    breakout_chars.append(set([';']))

            # Catching src=javascript:... 
            if re.match('javascript:', attr_val):
                # Scared this is too lenient. Possible source of false positives?
                if dquote_open and not squote_open:
                    breakout_chars.append(set([';']))
                elif squote_open and not dquote_open:
                    breakout_chars.append(set([';']))

            # Catching src=vbscript:... 
            # Exploit: msgbox (document.domain)
            elif re.match('vbscript:', attr_val):
                if dquote_open and not squote_open:
                    breakout_chars.append(set(['x']))
                elif squote_open and not dquote_open:
                    breakout_chars.append(set(['x']))


        # If no quotes are open or they're just not found:
        else:
            # means you can inject your own attribute value like:
            # x src=http://exploit.com
            if tag in ['script', 'frame', 'iframe']:
                breakout_chars.append(set([':', ')', '(']))
            else:
                #print '\n\n\n\n\n NO QUOTeS OPEN BUT FOUND INJECTION IN ATTRIBUTE TAG', tag, attr, attr_val, delim, payload, '\n\n\n\n\n'
                # Hail mary, no quotes found but definitely inside attr
                breakout_chars.append(set(['"', "'", ">", "<"]))

        return breakout_chars, line + payload_from_body

    def get_quote_context(self, line):
        ''' Goes through char by char to determine if double
        or single quotes are open or not: True/None '''
        dquote_open = None
        squote_open = None
        for c in line:
            if c == '"':
                dquote_open = self.opposite(dquote_open)
            elif c == "'":
                squote_open = self.opposite(squote_open)

        return dquote_open, squote_open

    def opposite(self, obj):
        ''' Returns the obj as either True or None '''
        if obj:
            obj = None
        else:
            obj = True
        return obj

    def comment_breakout(self, split_body, tag, payload_from_body):
        breakout_chars = []
        split_delim = '<' + tag
        # Get the final string in the list of splits because that's the closest one to
        # our injection point
        line = split_delim + split_body.split(split_delim)[-1]
        breakout_chars.append(set(['>']))
        return breakout_chars, line + payload_from_body

    def get_lxml_matches(self, full_match, body, resp_url, delim):
            # Replace the payloaded string with just the delim string (minus the ; )
            sub = delim+'subbed'
            subbed_num_text = re.subn(full_match, sub, body)
            num = subbed_num_text[1]
            subbed_body = subbed_num_text[0]
            try:
                doc = lxml.html.fromstring(subbed_body)
            except lxml.etree.ParserError:
                spider.log('ParserError from lxml on %s' % resp_url)
                return
            except lxml.etree.XMLSyntaxError:
                spider.log('XMLSyntaxError from lxml on %s' % resp_url)
                return

            x_injections = self.xpath_inj_points(sub, doc)
            if x_injections:
                return x_injections

    def combine_inj_data(self, injections, full_matches, scolon_matches, delim):
        ''' Combine lxml injection data with the 2 regex injection search data '''

        all_injections = []
        unfiltered_chars = None

        for idx, match in enumerate(full_matches):
            line, tag, attr, attr_val = self.parse_injections(injections[idx])
            unfiltered_chars = self.get_unfiltered_chars(match[1], delim)

            # Check if a colon needs to be added to the unfiltered chars
            for scolon_match in scolon_matches:
                # Confirm the string offset of the match is the same
                # Since scolon_match will only exist when ;9 was found
                if match[0] == scolon_match[0]:
                    unfiltered_chars += ';'
                    break

            all_injections.append((match[0], match[1], unfiltered_chars, line, tag, attr, attr_val))

        all_injections.sort()
        return all_injections

    def payloaded_lines(self, body, payload):
        pl_lines_found = sorted([])
        for line in body.splitlines():
            if payload in line:
                pl_lines_found.append(line)
        return pl_lines_found

    def make_item(self, meta, resp_url, lines, unfiltered):
        item = vuln()
        ''' Create the vuln item '''

        item['lines'] = lines.strip()
        item['xss_payload'] = meta['payload'] + ';'
        item['unfiltered'] = unfiltered
        item['xss_param'] = meta['xss_param']
        item['xss_place'] = meta['xss_place']
        item['orig_url'] = meta['orig_url']
        item['resp_url'] = resp_url
        if 'POST_to' in meta:
            item['POST_to'] = meta['POST_to'] 

        return item

    def parse_injections(self, injection):
        parent = None
        attr = None
        attr_val = None
        line = injection[0]
        tag = injection[1].lower()
        if len(injection) > 2: # attribute injections have 4 data points within this var
            attr = injection[2].lower()
            attr_val = injection[3].lower()
            if attr_val[-2:] == ';9':
                attr_val = attr_val[:-2]

        return line, tag, attr, attr_val

    def xpath_inj_points(self, search_str, doc):
        ''' Searches lxml doc for any text, attributes, or comments
        that reflect the subbed text '''
        injections = []

        # Why this xpath is wrong: perm.ly/dom4j-xpath-contains 
        #text_xss = doc.xpath("//*[contains(text(), '%s')]" % search_str)

        # Will this find DB error message stuff without a tag? No. It will not.
        #text_xss = doc.xpath("//*[text()]")#[contains(.,'%s')]]" % search_str)

        # Return all text nodes that contain the search_str
        text_xss = doc.xpath("//text()[contains(., '%s')]" % search_str)

        # Returns parent elements //* with any attribute [@* that
        # contains a value with search_str in it [contains(., '%s')]
        attr_xss = doc.xpath("//*[@*[contains(., '%s')]]" % search_str)

        # Return any comment that contains certain text
        comment_xss = doc.xpath("//comment()[contains(., '%s')]" % search_str)

        attr_inj = self.parse_attr_xpath(attr_xss, search_str)
        comm_inj = self.parse_comm_xpath(comment_xss, search_str)
        text_inj = self.parse_text_xpath(text_xss, search_str)

        injects = [attr_inj, comm_inj, text_inj]
        for i in injects:
            for x in i:
                injections.append(x)
        injections.sort()

        if len(injections) > 0:
            return injections

    def parse_attr_xpath(self, xpath, search_str):
        ''' Find all tags with attributes that contain the subbed str '''
        attr_inj = []
        for x in xpath:
            # x = http://lxml.de/api/lxml.etree._Element-class.html
            tag = x.tag
            line = x.sourceline
            items = x.items()
            for i in items:
                #a = (attr, attr_val)
                attr = i[0]
                attr_val = i[1]
                found = re.findall(search_str, attr_val)
                for f in found:
                    attr_inj.append((line, tag, attr, attr_val))
        return attr_inj

    def parse_comm_xpath(self, xpath, search_str):
        ''' Parse the xpath comment search findings '''
        comm_inj = []
        for x in xpath:
            parent = x.getparent()
            text = x.text
            found = re.findall(search_str, text)
            for f in found:
                line = parent.sourceline
                # Set this tag so when we split the final line
                # We split it at '<' + tag so that gives us
                # a split at <!--
                tag = '!--'
                comm_inj.append((line, tag))
        return comm_inj

    def parse_text_xpath(self, xpath, search_str):
        ''' Creates injection points for the xpath that finds the payload in any html enclosed text '''
        text_inj = []
        for x in xpath:
            parent = x.getparent()
            # In case parent is a Comment()
            while callable(parent.tag):
                parent = parent.getparent()
            tag = parent.tag
            found = re.findall(search_str, x.strip())
            line = parent.sourceline
            for f in found:
                text_inj.append((line, tag))
        return text_inj

    def unescape_payload(self, payload):
        ''' Unescape the various payload encodings (html and url encodings)'''
        if '%' in payload:
            payload = urllib.unquote_plus(payload)
            #if '%' in payload: # in case we ever add double url encoding like %2522 for dub quote
            #    payload = urllib.unquote_plus(payload)
        # only html-encoded payloads will have & in them
        payload = HTMLParser.HTMLParser().unescape(payload)

        return payload

    def process_body(self, body, match, payload):
        lines = []
        html_lines = body.splitlines()
        for idx, line in enumerate(html_lines):
            line = line.strip()
            if match in line:
                quote, js_quote = self.get_quote_enclosure(line, match, payload)
                num_txt = (idx, line)
                lines.append(num_txt)

        if len(lines) > 0:
            return lines, quote, js_quote

    def opposite_quote(self, quote):
        ''' Return the opposite quote of the one give, single for double or
        double for single '''
        if quote == '"':
            oppo_quote = "'"
        else:
            oppo_quote = '"'
        return oppo_quote

    def get_unfiltered_chars(self, payload, delim):
        ''' Check for the special chars and append them to a master list of tuples, one tuple per injection point '''

        unfiltered_chars = []
        # Change the delim+test_str+delim payload to just test_str
        # Make sure js payloads remove escaped ' and ", also remove ;
        # since ; will show up in html encoded entities. If ; is unfiltered
        # it will be added after this function
        #escaped_chars = re.findall(r'\\(.)', chars)
        chars_found = payload.replace(delim, '').replace("\\'", "").replace('\\"', '').replace(';', '')

        # List for just the inj point
        for c in chars_found:
            if c in self.test_str:
                unfiltered_chars.append(c)

        unfiltered_chars = ''.join(unfiltered_chars)

        if len(unfiltered_chars) > 0:
            return unfiltered_chars
        else:
            return ''

    def url_item_filtering(self, item, spider):
        ''' Make sure we're not just repeating the same URL XSS over and over '''

        if item['xss_place'] == 'url':

            if len(self.url_param_xss_items) > 0:

                for i in self.url_param_xss_items:
                    # If the injection param, the url up until the injected param and the payload
                    # are all the same as a previous item, then don't bother creating the item

                    # Match tags where injection point was found
                    if item['xss_param'] == i['xss_param']:

                        # Match the URL up until the params
                        if item['orig_url'].split('?', 1)[0] == i['orig_url'].split('?', 1)[0]:

                            # Match the payload
                            if item['xss_payload'] == i['xss_payload']:

                                # Match the unfiltered characters
                                if item['unfiltered'] == i['unfiltered']:

                                    raise DropItem('Duplicate item found: %s' % item['orig_url'])

            self.url_param_xss_items.append(item)

        return item

    def event_attributes(self):
        ''' HTML tag attributes that allow javascript TAKEN OUT AT THE MOMENT'''

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
        return event_attributes

    def write_to_file(self, item, spider):
        with open('formatted-vulns.txt', 'a+') as f:
            f.write('\n')

            f.write('URL: '+item['orig_url']+'\n')
            spider.log('    URL: '+item['orig_url'], level='INFO')

            f.write('response URL: '+item['resp_url']+'\n')
            spider.log('    response URL: '+item['resp_url'], level='INFO')

            if 'POST_to' in item:
                f.write('POST url: '+item['POST_to']+'\n')
                spider.log('    POST url: '+item['POST_to'], level='INFO')

            f.write('Unfiltered: '+item['unfiltered']+'\n')
            spider.log('    Unfiltered: '+item['unfiltered'], level='INFO')

            f.write('Payload: '+item['xss_payload']+'\n')
            spider.log('    Payload: '+item['xss_payload'], level='INFO')

            f.write('Type: '+item['xss_place']+'\n')
            spider.log('    Type: '+item['xss_place'], level='INFO')

            f.write('Injection point: '+item['xss_param']+'\n')
            spider.log('    Injection point: '+item['xss_param'], level='INFO')

            f.write('Line: '+item['lines']+'\n')
            spider.log('    Line: '+item['lines'], level='INFO')

            if 'error' in item:
                f.write('Error: '+item['error']+'\n')
                spider.log('    Error: '+item['error'], level='INFO')

# Reverse tag search
#            nearest_tag_offset = re.search('[a-zA-Z]+?<', reverse_body).end()
#            tag_to_payload = split_body[-nearest_tag_offset:]
#            print 'TAG TO PAYLOAD', tag_to_payload
