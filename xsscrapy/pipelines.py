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

class XSSCharFinder(object):
    def __init__(self):
        self.redir_pld = 'JaVAscRIPT:prompt(99)'
        self.test_str = '\'"(){}=<x>:'
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
            if len(re_matches) != len(lxml_match_data):
                print '***************MISMATCH**********************'
                print resp_url
                item['error'] = 'Mismatch: html parsed vs regex parsed injections, %d vs %d. Higher chance of false positive' % (len(injections), len(full_matches))
                mismatch = True

            inj_data = self.combine_inj_data(lxml_match_data, re_matches, scolon_matches, delim)
            for i in inj_data:
                ########## XSS LOGIC #############
                item = self.xss_logic(i, meta, resp_url, body)
                if item:
                    if item['xss_place'] == 'url':
                        item = self.url_item_filtering(item, spider)
                    self.write_to_file(item, spider)
                    return item

        # Catch all test payload chars no delims
        # Catches DB errors
        #pl_lines_found = self.payloaded_lines(body, orig_payload)
        #if pl_lines_found:
        #    print '\n\n\n      PLOADED LINES LAST REOSRT\n     %s %s %s \n\n\n' % (resp_url, meta['xss_place'], meta['xss_param'])
        #    return self.make_item(meta, resp_url, pl_lines_found, orig_payload)
        raise DropItem('No XSS vulns in %s. type = %s, %s, %s'% (resp_url, meta['xss_place'], meta['xss_param'], meta['payload']))

    def xss_logic(self, injection, meta, resp_url, body):
        ''' XSS logic. Returns None if vulnerability not found 
        The breakout_chars var is a list(set()). This ensure we can
        test for breakout given OR statements, like " or ; to breakout'''
        print 'xss_logic:', injection

        offset, payload, unfiltered, sourceline, tag, attr, attr_val = injection

######## CHANGE FROM line TO lines HAPPENS HERE
        if unfiltered:
            breakout_chars, lines = self.get_breakout_chars(injection, body)
            if breakout_chars:
                # Test for self.redir payload
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
        tag = injection[4]
        attr = injection[5]
        attr_val = injection[6]
        split_body = body[:match_offset]
        payload = injection[1]
        delim = payload[:7]

        # Do comments first since they're just 1 char
        if tag == 'comment':
            breakout_chars, line = self.comment_breakout(split_body)

        # Then check attribute breakouts
        elif attr:
            # tag == script: try ...
            breakout_chars, line = self.attr_breakout(split_body, tag, attr, attr_val, delim)

        # Finally check between tag breakout
        else:
            breakout_chars, line = self.tag_breakout(split_body, tag)

        if breakout_chars:
            return breakout_chars, line
        else:
            return None, None

    def tag_breakout(self, split_body, tag):
        breakout_chars = []
        split_delim = '>'
        line = split_delim + split_body.split(split_delim)[-1] + 'INJECTION'

        breakout_chars.append(set('>'))

        # Look for javascript breakouts
        if tag == 'script':
            # Get rid of javascript escaped quotes
            line = line.replace('\\"', '').replace("\\'", "")
            dquote_open, squote_open = self.get_quote_context(line)
            if dquote_open:
                breakout_chars.append(set(['"']))
            if squote_open:
                breakout_chars.append(set(["'"]))
            # If neither double nor single quotes are open at injection point, we just need a ;
            if not dquote_open and not squote_open:
                breakout_chars.append(set([';']))

        return breakout_chars, line

    def attr_breakout(self, split_body, tag, attr, attr_val, delim):
        breakout_chars = []
        #Find the nearest <tag
        split_delim = '<'+tag
        line = split_delim + split_body.split(split_delim)[-1] + 'INJECTION'
        # Get rid of javascript escaped quotes

        # javascript:alert(1) vuln
        if tag == 'a' and attr == 'href' and attr_val == delim+'subbed':
            # Only need : ( and ) to use javascript:prompt(4) redir payload
            breakout_chars.append(set([':', ')', '(']))

        # frame source vuln, again javascript:alert(1)
        elif tag in ['frame', 'iframe'] and attr == 'src' and attr_val == delim+'subbed':
            breakout_chars.append(set([':', ')', '(']))

        # Check if quotes even exist in the line
        elif '"' in line or "'" in line:
            line = line.replace('\\"', '').replace("\\'", "")
            dquote_open, squote_open = self.get_quote_context(line)
            if dquote_open:
                breakout_chars.append(set(['"']))
            if squote_open:
                breakout_chars.append(set(["'"]))

        # If no quotes are open or they're just not found:
                #if c == 
        return breakout_chars, line

    def get_quote_context(self, line):
        ''' Goes through char by char to determine if double
        or single quotes are open or not: True/None '''
        dquote_open = None
        squote_open = None
        for c in line:
            if c == '"':
                dquote_open = self.opposite(dquote_open)
                print 'dquote changed', dquote_open
            elif c == "'":
                squote_open = self.opposite(squote_open)
                print 'squote changed', squote_open

        return dquote_open, squote_open

    def opposite(self, obj):
        ''' Returns the obj as either True or None '''
        if obj:
            obj = None
        else:
            obj = True
        return obj

    def comment_breakout(self, split_body):
        breakout_chars = []
        split_delim = '<'
        # Get the final string in the list of splits because that's the closest one to
        # our injection point
        line = split_delim + split_body.split(split_delim)[-1] + 'INJECTION'
        breakout_chars.append(set(['>']))
        return breakout_chars, line

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
                return []
            except lxml.etree.XMLSyntaxError:
                spider.log('XMLSyntaxError from lxml on %s' % resp_url)
                return []

            x_injections = self.xpath_inj_points(sub, doc)
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

        item['lines'] = lines
        item['xss_payload'] = meta['payload'] + ';'
        item['unfiltered'] = unfiltered
        item['xss_param'] = meta['xss_param']
        item['xss_place'] = meta['xss_place']
        item['orig_url'] = meta['orig_url']
        item['resp_url'] = resp_url
        if 'POST_to' in meta:
            item['POST_to'] = meta['POST_to'] 

############### print shit ###################
#        print ''
#        print '    URL:', item['resp_url']
#        print '    xss_place:', item['xss_place']
#        print '    xss_param:', item['xss_param']
#        print '       Line: ', item['lines']
#        if 'error' in item:
#            print '    Error:', item['error']
#        print '------------------------------------------'
#
        return item

    def parse_injections(self, injection):
        parent = None
        attr = None
        attr_val = None
        line = injection[0]
        tag = injection[1]
        if len(injection) > 2: # attribute injections have 4 data points within this var
            attr = injection[2]
            attr_val = injection[3]
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

        if len(injections) > 0:
            return sorted(injections)

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
            text = x.text
            found = re.findall(search_str, text)
            for f in found:
                line = x.getparent().sourceline
                tag = 'comment'
                comm_inj.append((line, tag))
        return comm_inj

    def parse_text_xpath(self, xpath, search_str):
        ''' Creates injection points for the xpath that finds the payload in any html enclosed text '''
        text_inj = []
        for x in xpath:
            parent = x.getparent()
            tag = parent.tag
            line = parent.sourceline
            found = re.findall(search_str, x.strip())
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


        # For js payloads, just count how many quotes there are
       # elif payload == self.js_pld:
       #     if '<' not in line:
       #         # Then we can be almost sure it's pure JS
       #         squote = re.findall('\'', line)
       #         dquote = re.findall('"', line)
       #        
       #        if len(squote) == len(dquote):
       #            #Guess the first quote that pops up as html attr quote
       #            quote = re.search('(\'|")', line)

       #            if 


       #            return quote, js_quote




       #         if len(squote) > len(dquote):
       #             quote = squote[0]
       #             js_quote = dquote[0]
       #         else:
       #             quote = dquote[0]
       #             js_quote = squote[0]

       #             return quote, js_quote
   #         else:
   #             squote = re.findall('\'', line)
   #             dquote = re.findall('"', line)
   #     # For tag or attribute payloads, count how many quotes after = there are
   #     else:
   #         squote = re.findall('.=(\')', line)
   #         dquote = re.findall('.=(")', line)

   #     # If no quotes are found on the line then search the body
   #     if len(squote) == 0 and len(dquote) == 0:
   #         if payload == self.js_pld:
   #             squote = re.findall('\'', body)
   #             dquote = re.findall('"', body)
   #         # For tag or attribute payloads, count how many quotes after = there are
   #         else:
   #             squote = re.findall('.=(\')', body)
   #             dquote = re.findall('.=(")', body)

   #     if len(squote) > len(dquote):
   #         quote = "'"
   #     else:
   #         quote = '"'

   #     if quote == '"':
   #         js_quote = "'"
   #     else:
   #         js_quote = '"'

        return quote, js_quote

    def get_unfiltered_chars(self, payload, delim):
        ''' Check for the special chars and append them to a master list of tuples, one tuple per injection point '''

        unfiltered_chars = []
        # Change the delim+test_str+delim payload to just test_str
        # Make sure js payloads remove escaped ' and "
        #escaped_chars = re.findall(r'\\(.)', chars)
        chars_found = payload.replace(delim, '').replace("\\'", "").replace('\\"', '')

        # List for just the inj point
        for c in chars_found:
            if c in self.test_str:
                unfiltered_chars.append(c)

        if len(unfiltered_chars) > 0:
            return ''.join(unfiltered_chars)

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

        # Check the entire body for exact match
        # Escape out all the special regex characters to search for the payload in the html body
       # re_payload = escaped_payload.replace('(', '\(').replace(')', '\)').replace('"', '\\"').replace("'", "\\'")
       # re_payload = re_payload.replace('{', '\{').replace('}', '\}').replace(']', '\]').replace('[', '\[')
       # re_payload = '.{1}?'+re_payload
       # full_matches = re.findall(re_payload, body)
       # for f in full_matches:
       #     unescaped_match = ''.join(self.get_unfiltered_chars(f, escaped_payload))
       #     if unescaped_match == escaped_payload:
       #         #if '\\' == unescaped_match[0]:
       #         #    continue
       #         item['error'] = 'Response passed injection point specific search without success, checked for exact payload match in body (higher chance of false positive here)'
       #         item['line'] = self.get_inj_line(body, f)[0]
       #         item['xss_payload'] = orig_payload
       #         item['unfiltered'] = escaped_payload
       #         item['xss_param'] = xss_param
       #         item['xss_place'] = xss_place
       #         item['url'] = meta['orig_url']
       #         if POST_to:
       #             item['POST_to'] = POST_to
       #         print 'OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOoo           MARKER'
       #         return item

#        unfiltered_chars = [''.join(self.get_unfiltered_chars(match, orig_payload))
#                           for match in re.findall(chars_between_delims, body)]
#        match_offsets = [m.start() for m in re.finditer(full_match, body)]
#        offset_unfil_chars = zip(match_offsets, unfiltered_chars)
#
#        for x in offset_unfil_chars:
#            index = 0
#            index += 1
#            offset = x[0]
#            unfil_chars = x[1]
#            context_str = re.subn(chars_between_delims, 'xxx',body[:offset])[0]
#            if context_str[-1] in ['"', "'"]:
#                breakout = context_str[-1]
#                print context_str
#                print '        *****    BREAKOUT =', breakout
#
#        for line in body.splitlines():
#            matches = re.findall(chars_between_delims, line)
#            if matches:
#                for match in enumerate(matches):
#                    unfiltered_chars = self.get_unfiltered_chars(match, escaped_payload)
#                    if unfiltered_chars:
#                        joined_chars = ''.join(unfiltered_chars)
#                        chars = set(joined_chars)
#
#                        ###### XSS RULES ########
#                        # Process the line and failing that process the body
#                        line_html, quote, js_quote = process_body(body, match, escaped_payload)
#
#                        print 'quote: ', quote
#                        print 'js_quote: ', js_quote
#
#                        break_tag_chars = set(['>', '<'])
#                        break_attr_chars = set([quote])
#                        break_js_chars = set([js_quote, ';'])
#
#                        # Redirect
#                        if self.redir_pld.lower() == escaped_payload.lower():
#                            if attr == 'href' and orig_payload.lower() == match.lower():
#                                item = self.make_item(joined_chars, xss_place, orig_payload, tag, meta['orig_url'], xss_param, line_html, POST_to, item)
#                                item = self.url_item_filtering(item, spider)
#                                return item
#                            if tag == 'frame' and attr == 'src':
#                                if orig_payload.lower() == match.lower():
#                                    item = self.make_item(joined_chars, xss_place, orig_payload, tag, meta['orig_url'], xss_param, line_html, POST_to, item)
#                                    item = self.url_item_filtering(item, spider)
#                                    return item
#
#                        # JS breakout
#                        elif self.js_pld == escaped_payload: #js chars
#                            if break_js_chars.issubset(chars):
#                                item = self.make_item(joined_chars, xss_place, orig_payload, tag, meta['orig_url'], xss_param, line_html, POST_to, item)
#                                item = self.url_item_filtering(item, spider)
#                                return item
#
#                        # Attribute breakout
#                        if attr:
#                            if quote in escaped_payload:
#                                if break_attr_chars.issubset(chars):
#                                    item = self.make_item(joined_chars, xss_place, orig_payload, tag, meta['orig_url'], xss_param, line_html, POST_to, item)
#                                    item = self.url_item_filtering(item, spider)
#                                    return item
#
#                        # Tag breakout
#                        else:
#                            if '<' and '>' in escaped_payload:
#                                if break_tag_chars.issubset(chars):
#                                    item = self.make_item(joined_chars, xss_place, orig_payload, tag, meta['orig_url'], xss_param, line_html, POST_to, item)
#                                    item = self.url_item_filtering(item, spider)
#                                    return item
#
#        # In case it slips by all of the filters, then we move on
#        raise DropItem('No XSS vulns in %s. Tested: type = %s, injection point = %s' % (resp_url, xss_place, xss_param))

#    def get_quote_enclosure(self, search_txt, match, payload):
#        ''' Figure out which quote is for JS and which is for html '''
#
#        if '"' in search_txt or "'" in search_txt:
#            # At least one quote in in the body or line
#            # See if there's any html attributes in the line
#            # If there's no attr_quote then just go to the next test
#            attr_quotes = re.findall(r'<\w[^>]\w+=(.)', a)
#            if attr_quote:
#                for q in attr_quote:
#                    if q in ['"', "'"]:
#                        quote = q
#                        js_quote = self.oppo_quote(quote)
#                        return quote, js_quote
#
#            # No html attribute quotes found
#            ##if escaped_payload == self.js_pld:
#
#
#
#
#
#            #if payload == self.js_pld:
#                #Then we know we're trying to look inside javascript
#                if '<' not in line:
#                    # Then we can be almost sure it's pure JS
#                    quote = max(squote, dquote)
#                    js_quote = get_js_quote(quote)
#                    return quote, js_quote
#                else:
#
#
#
#                #Quotes in line but payload == (redir or test_str)
#                #Assuming test_str
#                else:
#                    quote, js_quote = quote_finder(search_txt)
#
#            # Quotes are only in the body
#            else:
#                quote = quote = re.search('(\'|")', search_txt)
#                js_quote = oppo_quote(quote)
#                return quote, js_quote
#
#        # Quotes are not in the body or the line
#        else:
#            quote = '"'
#            js_quote = oppo_quote(quote)
#            return quote, js_quote
#
#    def quote_finder(self, search_txt):
#        ''' Search text for quote if you know it already has either ' or " '''
#        squote = re.findall('\'', search_txt)
#        dquote = re.findall('"', search_txt)
#
#        # Can't be zero
#        if len(squote) == len(dquote):
#            #Guess the first quote that pops up as html attr quote
#            quote = re.search('(\'|")', search_txt)
#            js_quote = oppo_quote(quote)
#        else:
#            # Return the higher number of results as the html quote 
#            quote = max(squote, dquote)
#            js_quote = get_js_quote(quote)
#
#        return quote, js_quote

#    def make_item(self, meta joined_chars, xss_place, orig_payload, tag, meta['orig_url'], xss_param, line, item):
#        ''' Create the vulnerable item '''
#
#        item['line'] = line
#        item['xss_payload'] = orig_payload
#        item['unfiltered'] = joined_chars
#        item['xss_param'] = xss_param
#        item['xss_place'] = xss_place
#        item['inj_tag'] = tag
#        item['url'] = meta['orig_url']
#        if POST_to:
#            item['POST_to'] = meta['POST_to'] 
#        return item

