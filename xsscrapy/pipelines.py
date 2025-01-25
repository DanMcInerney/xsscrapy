from html import unescape
from scrapy.http import Response
from xsscrapy.spiders.xss_spider import XSSspider
from scrapy.exceptions import DropItem
from xsscrapy.items import vuln
import re
from lxml import html
from socket import gaierror, gethostbyname
from urllib.parse import unquote_plus, urlparse
from logging import INFO


class XSSCharFinder(object):
    def __init__(self):
        self.url_param_xss_items = []

    def get_filename(self, url: str):
        filename = 'xsscrapy-vulns.txt'
        up = urlparse(url).netloc.replace('www.', '').split(':')[0]
        if up:
            filename = up + '.txt'
        return filename

    def open_spider(self, spider: XSSspider):
        self.filename = self.get_filename(spider.url)

    def process_item(self, item: vuln, spider: XSSspider):
        response: Response = item['resp']
        meta = response.meta

        payload: str = meta['payload']
        delim = meta['delim']
        resp_url = response.url
        body: str = response.text
        mismatch = False
        error = None
        fuzz_payload = payload.replace(delim, '').replace(
            ';9', '')  # xss char payload
        # Regex: ( ) mean group 1 is within the parens, . means any char,
        # {1,80} means match any char 0 to 80 times, 80 chosen because double URL encoding
        # ? makes the search nongreedy so it stops after hitting its limits
        full_match = f'{delim}.{{0,80}}?{delim}'
        # matches with semicolon which sometimes cuts results off
        sc_full_match = f'{delim}.{{0,80}}?{delim};9'

        # Quick sqli check based on DSSS
        dbms, regex = self.sqli_check(body, meta['orig_body'])
        if dbms:
            msg = f'Possible SQL injection error! Suspected DBMS: {dbms}, regex used: {regex}'
            item = self.make_item(meta, resp_url, msg, 'N/A', None)
            self.write_to_file(item, spider)
            return None

        # Check for script tags pointing to a non-registered domain
        unclaimed_url = self.unclaimed_url_check(response.body)
        if unclaimed_url:
            msg = f'Found non-registered domain in script tag! Non-registered URL: {unclaimed_url}'
            self.log_to_file(msg, resp_url, spider)

        # Now that we've checked for SQLi, we can lowercase the body
        body = body.lower()

        # XSS detection starts here
        re_matches = sorted([(m.start(), m.group(), m.end())
                            for m in re.finditer(full_match, body)])

        if re_matches:
            lxml_injs = self.get_lxml_matches(
                full_match, body, resp_url, delim)
            if lxml_injs:
                if len(re_matches) != len(lxml_injs):
                    spider.log(
                        f'Error: mismatch in injections found by lxml and regex; higher chance of false positive for {resp_url}'
                    )
                    error = 'Error: mismatch in injections found by lxml and regex; higher chance of false positive'
                    mismatch = True

                inj_data = self.combine_regex_lxml(
                    lxml_injs, re_matches, body, mismatch, payload, delim, spider)
                # If mismatch is True, then "for offset in sorted(inj_data)" will fail with TypeError
                # Handle potential TypeErrors from sorted() on inj_data
                try:
                    for offset in sorted(inj_data):
                        ########## XSS LOGIC #############
                        item = self.xss_logic(
                            inj_data[offset], meta, resp_url, error)
                        if item:
                            item = self.url_item_filtering(item)
                            if mismatch:
                                item[
                                    'error'] = f'Mismatch: html parsed vs regex parsed injections, {len(inj_data)} vs {len(re_matches)}. Higher chance of false positive'
                            self.write_to_file(item, spider)
                            return item
                except TypeError:
                    if not mismatch:
                        raise  # Only raise if it's not a mismatch
                    return
                except Exception as e:
                    spider.log(f"Unexpected error: {e}")
            # No lxml_match_data
            else:
                spider.log('Error: regex found injection, but lxml did not')

        # Catch all test payload chars no delims
        pl_lines_found = self.payloaded_lines(body, fuzz_payload)
        if pl_lines_found:
            item = self.make_item(
                meta, resp_url, pl_lines_found, fuzz_payload, None
            )
            if item:
                item = self.url_item_filtering(item)
                item['error'] = 'Payload delims do not surround this injection point. Found via search for entire payload.'
                self.write_to_file(item, spider)
                return item

        raise DropItem(
            f'No XSS vulns in {resp_url}. type = {meta["xss_place"]}, {meta["xss_param"]}')

    def log_to_file(self, msg, resp_url, spider):
        """Helper function to log messages to file and the spider log."""
        with open(self.filename, 'a+') as f:
            f.write('\n')
            f.write(f'URL: {resp_url}\n')
            spider.log(f'    URL: {resp_url}\n', level=INFO)
            f.write(f'{msg}\n')
            spider.log(f'    {msg}\n', level=INFO)

    def sqli_check(self, body: str, orig_body: str):
        """
        Perform a quick lookup in the response body for SQL errors.
        Uses detection methods from w3af's and DSSS.py's libraries,
        focusing on the more effective DSSS methods.
        """

        # Mapping of DBMS to their corresponding error regex patterns
        DBMS_ERRORS = {
            "MySQL":                [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_.*",
                r"valid MySQL result",
                r"MySqlClient\."
            ],
            "PostgreSQL":           [
                r"PostgreSQL.*ERROR",
                r"Warning.*\Wpg_.*",
                r"valid PostgreSQL result",
                r"Npgsql\."
            ],
            "Microsoft SQL Server": [
                r"Driver.* SQL[\-\_\ ]*Server",
                r"OLE DB.* SQL Server",
                r"(\W|\A)SQL Server.*Driver",
                r"Warning.*mssql_.*",
                r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
                r"(?s)Exception.*\WSystem\.Data\.SqlClient\.",
                r"(?s)Exception.*\WRoadhouse\.Cms\."
            ],
            "Microsoft Access":     [
                r"Microsoft Access Driver",
                r"JET Database Engine",
                r"Access Database Engine"
            ],
            "Oracle":               [
                r"ORA-[0-9]{4}",  # Simplified to just look for ORA-xxxx format
                r"Oracle error",
                r"Oracle.*Driver",
                r"Warning.*\Woci_.*",
                r"Warning.*\Wora_.*"
            ]
        }

        # Check each DBMS and its associated regex patterns
        for dbms, patterns in DBMS_ERRORS.items():
            for pattern in patterns:
                if re.search(pattern, body, re.I) and not re.search(pattern, orig_body, re.I):
                    return dbms, pattern

        return None, None

        # Taken from w3af
        # SQL_errors = ("System.Data.OleDb.OleDbException",
        #              "[SQL Server]",
        #              "[Microsoft][ODBC SQL Server Driver]",
        #              "[SQLServer JDBC Driver]",
        #              "[SqlException",
        #              "System.Data.SqlClient.SqlException",
        #              "Unclosed quotation mark after the character string",
        #              "'80040e14'",
        #              "mssql_query()",
        #              "odbc_exec()",
        #              "Microsoft OLE DB Provider for ODBC Drivers",
        #              "Microsoft OLE DB Provider for SQL Server",
        #              "Incorrect syntax near",
        #              "Sintaxis incorrecta cerca de",
        #              "Syntax error in string in query expression",
        #              "ADODB.Field (0x800A0BCD)<br>",
        #              "ADODB.Recordset'",
        #              "Unclosed quotation mark before the character string",
        #              "'80040e07'",
        #              "Microsoft SQL Native Client error",
        #              "SQLCODE",
        #              "DB2 SQL error:",
        #              "SQLSTATE",
        #              "[CLI Driver]",
        #              "[DB2/6000]",
        #              "Sybase message:",
        #              "Sybase Driver",
        #              "[SYBASE]",
        #              "Syntax error in query expression",
        #              "Data type mismatch in criteria expression.",
        #              "Microsoft JET Database Engine",
        #              "[Microsoft][ODBC Microsoft Access Driver]",
        #              "Microsoft OLE DB Provider for Oracle",
        #              "wrong number or types",
        #              "PostgreSQL query failed:",
        #              "supplied argument is not a valid PostgreSQL result",
        #              "unterminated quoted string at or near",
        #              "pg_query() [:",
        #              "pg_exec() [:",
        #              "supplied argument is not a valid MySQL",
        #              "Column count doesn\'t match value count at row",
        #              "mysql_fetch_array()",
        #              "mysql_",
        #              "on MySQL result index",
        #              "You have an error in your SQL syntax;",
        #              "You have an error in your SQL syntax near",
        #              "MySQL server version for the right syntax to use",
        #              "Division by zero in",
        #              "not a valid MySQL result",
        #              "[MySQL][ODBC",
        #              "Column count doesn't match",
        #              "the used select statements have different number of columns",
        #              "DBD::mysql::st execute failed",
        #              "DBD::mysql::db do failed:",
        #              "com.informix.jdbc",
        #              "Dynamic Page Generation Error:",
        #              "An illegal character has been found in the statement",
        #              "[Informix]",
        #              "<b>Warning</b>:  ibase_",
        #              "Dynamic SQL Error",
        #              "[DM_QUERY_E_SYNTAX]",
        #              "has occurred in the vicinity of:",
        #              "A Parser Error (syntax error)",
        #              "java.sql.SQLException",
        #              "Unexpected end of command in statement",
        #              "[Macromedia][SQLServer JDBC Driver]",
        #              "could not prepare statement",
        #              "Unknown column",
        #              "where clause",
        #              "SqlServer",
        #              "syntax error")
        # for e in SQL_errors:
        #    if e in body and e not in orig_body:
        #        return e

    def unclaimed_url_check(self, body: bytes):
        """Check for unregistered domains in script tag URLs within the HTML body."""
        tree = html.fromstring(body)
        script_urls = tree.xpath('//script/@src')
        for url in script_urls:
            domain = urlparse(url).netloc
            try:
                gethostbyname(domain)
            except gaierror:
                return url

    def xss_logic(self, injection, meta, resp_url, error):
        """
        XSS logic. Returns None if vulnerability not found 
        The breakout_chars var is a list(set()). This ensure we can
        test for breakout given OR statements, like " or ; to breakout
        """
        # Gets rid of some false positives
        # ex: https://www.facebook.com/directory/pages/9zqjxpo'%22()%7B%7D%3Cx%3E:9zqjxpo;9
        # if len(unfiltered) > len(self.test_str):
        #    return
        # Unpack the injection
        # tag_index, tag, attr, attr_val, payload, unfiltered_chars, line = injection
        # get_unfiltered_chars() can only return a string 0+ characters, but never None
        unfiltered_chars = injection[5]
        # injection[6] sometimes == '<p' maybe?
        # It happened POSTing chatRecord to http://service.taobao.com/support/minerva/robot_save_chat_record.htm
        # that page returned a Connection: Close header and no body
        # THIS NEEDS TO BE THE REFLECTED PAYLOAD
        line = injection[6]
        item_found = None

        # get_reflected_chars() always returns a string
        if unfiltered_chars:
            chars_payloads: dict = self.get_breakout_chars(injection)
            # breakout_chars always returns a , never None
            if chars_payloads:
                sugg_payloads = []
                for chars, possible_payloads in chars_payloads.items():
                    if set(chars).issubset(set(unfiltered_chars)):
                        item_found = True
                        # Get rid of possible payloads with > in them if > not in unfiltered_chars
                        for possible_payload in possible_payloads:
                            if '>' not in unfiltered_chars or '>' not in possible_payload:
                                sugg_payloads.append(possible_payload)

                if item_found:
                    return self.make_item(meta, resp_url, line, unfiltered_chars, sugg_payloads)

    def get_breakout_chars(self, injection: tuple):
        """
        Returns either None if no breakout chars were found
        or a list of sets of potential breakout characters
        """

        _, tag, attr, attr_val, payload, _, line = injection
        pl_delim = payload[:6]
        full_match = '%s.{0,85}?%s' % (pl_delim, pl_delim)
        line = re.sub(full_match, 'INJECTION', line)

        all_chars_payloads = {}

        # Comment injection
        if tag == '!--':
            chars = ('>')
            # Corrected the SVG tag spelling
            payload = '--><svg onLoad=prompt(9)>'
            all_chars_payloads.get(chars, []).append(payload)

        # Attribute injection
        elif attr:
            chars_payloads = self.attr_breakout(
                tag, attr, attr_val, pl_delim, line)
            for k, payloads in chars_payloads.items():
                all_chars_payloads.get(k, []).extend(payloads)

        # Between tag injection
        else:
            chars_payloads = self.tag_breakout(tag, line)
            for k, payloads in chars_payloads.items():
                all_chars_payloads.get(k, []).extend(payloads)

        # Dedupe the list of potential payloads
        for chars in all_chars_payloads:
            all_chars_payloads[chars] = list(set(all_chars_payloads[chars]))

        return all_chars_payloads

    def decomment_js(self, line: str):
        """
        Remove commented JavaScript lines which interfere with quote detection.
        """
        lines = line.splitlines()
        decommented_lines = [
            l for l in lines if not l.strip().startswith('//')]
        return '\n'.join(decommented_lines)

    def tag_breakout(self, tag, line):
        """
        Generate potential payloads for breakout characters
        based on the provided tag and line.
        """

        chars_payloads = {}

        # Look for javascript breakouts
        if tag == 'script':

            # Get rid of comments which screw with the quote detector
            decommented_js = self.decomment_js(line)

            # Get rid of javascript escaped quotes
            dquote_open, squote_open = self.get_quote_context(decommented_js)
            if dquote_open:
                chars = ('"')
                payload = 'x";prompt(9);'
                try:
                    chars_payloads[chars].append(payload)
                except KeyError:
                    chars_payloads[chars] = [payload]

            if squote_open:
                chars = ("'")
                payload = "x';prompt(9);"
                try:
                    chars_payloads[chars].append(payload)
                except KeyError:
                    chars_payloads[chars] = [payload]

                chars = ('<', '>')
                payload = '<svG onLoad=prompt(9)>'
                try:
                    chars_payloads[chars].append(payload)
                except KeyError:
                    chars_payloads[chars] = [payload]

            # If neither double nor single quotes are open at injection point, we just need a ;
            if not dquote_open and not squote_open:
                chars = (";")
                payload = ';prompt(9);'
                try:
                    chars_payloads[chars].append(payload)
                except KeyError:
                    chars_payloads[chars] = [payload]

            chars = ("<", ">", "/")
            payload = '</SCript><svG/onLoad=prompt(9)>'
            try:
                chars_payloads[chars].append(payload)
            except KeyError:
                chars_payloads[chars] = [payload]

        # Everything that's not a script tag
        else:
            chars = ("<", ">")
            payload = '<svG onLoad=prompt(9)>'
            try:
                chars_payloads[chars].append(payload)
            except KeyError:
                chars_payloads[chars] = [payload]

        return chars_payloads

    def get_attr_quote(self, attr, line):
        """
        Return the first quote in the string which
        should always be the html quote if this is called
        on a string of html with an attr
        """
        split_line = line.split(attr, 1)
        if len(split_line) > 1:
            attr_split_line = attr + split_line[1]
            # Match the equal sign followed by optional spaces and then either ' or "
            match = re.search(r'=\s*?(\'|")', attr_split_line)
            attr_quote = re.search('=\s*?(\'|")', attr_split_line)
            if match:
                return match.group(1)
        return attr_quote

    def attr_breakout(
        self,
        tag: str,
        attr: str,
        attr_val: str,
        delim: str,
        line: str
    ):
        """
        Generate potential payloads for breakout characters
        based on the provided attribute and line.
        """
        chars_payloads = {}
        dquote_open, squote_open = self.get_quote_context(line)
        attr_quote = self.get_attr_quote(attr, line)

        # javascript:alert(1) vulns
        # We do this slicing operation because ;9 might be at the end
        # although it's unnecessary for the payload

        # CHECK HERE, PASS DOWN THE ORIG ATTR VAL
        # if delim+'subbed' in attr_val:
        if attr_val[:len(delim+'subbed')] == delim+'subbed':
            if tag == 'a' and attr == 'href':
                # Only need : ( and ) to use javascript:prompt(4) redir payload
                chars = (':', '(', ')')
                payload = 'JavaSCript:prompt(9)'
                try:
                    chars_payloads[chars].append(payload)
                except KeyError:
                    chars_payloads[chars] = [payload]

            # Inject the frame or script source file
            elif tag in ['script', 'frame', 'iframe']:
                if attr == 'src':
                    chars = (':', '(', ')')
                    payload = 'JavaSCript:prompt(9)'
                    try:
                        chars_payloads[chars].append(payload)
                    except KeyError:
                        chars_payloads[chars] = [payload]

        # Catching src=vbscript:...
        # Exploit: msgbox (document.domain)
        if re.match('vbscript:', attr_val):
            if dquote_open and squote_open:
                vbs_quote = self.opposite_quote(attr_quote)
                chars = ("x", vbs_quote)
                payload = vbs_quote + '%0a%0dMsgBox (xss)'
                try:
                    chars_payloads[chars].append(payload)
                except KeyError:
                    chars_payloads[chars] = [payload]

            else:
                chars = ("x")
                payload = "%0a%0dMsgBox (xss)"
                try:
                    chars_payloads[chars].append(payload)
                except KeyError:
                    chars_payloads[chars] = [payload]

        # Catching src=javascript:...
        if re.match('javascript:', attr_val):
            if dquote_open and squote_open:
                js_quote = self.opposite_quote(attr_quote)
                chars = (js_quote, ";")
                payload = js_quote+";prompt(9);"
                try:
                    chars_payloads[chars].append(payload)
                except KeyError:
                    chars_payloads[chars] = [payload]

            else:
                chars = (";")
                payload = ";prompt(9);"
                try:
                    chars_payloads[chars].append(payload)
                except KeyError:
                    chars_payloads[chars] = [payload]

        # Check for JS attributes
        if attr in self.event_attributes():
            if dquote_open and squote_open:
                js_quote = self.opposite_quote(attr_quote)
                chars = (";", js_quote)
                payload = 'x'+js_quote+';prompt(9);'+js_quote
                try:
                    chars_payloads[chars].append(payload)
                except KeyError:
                    chars_payloads[chars] = [payload]

            elif not dquote_open and not squote_open:
                chars = (";")
                payload = ';prompt(9);'
                try:
                    chars_payloads[chars].append(payload)
                except KeyError:
                    chars_payloads[chars] = [payload]

            # elif squote_open and not dquote_open:
            else:
                chars = (";")
                payload = ";prompt(9);"
                try:
                    chars_payloads[chars].append(payload)
                except KeyError:
                    chars_payloads[chars] = [payload]

        # Check if quotes even exist in the line
        if '"' in line or "'" in line:
            if not attr_quote:
                chars = ('<', '>')
                payload = 'x><svG onLoad=prompt(9)>'
                try:
                    chars_payloads[chars].append(payload)
                except KeyError:
                    chars_payloads[chars] = [payload]
            else:
                chars = (attr_quote)
                payload1 = 'x'+attr_quote+'><svG onLoad=prompt(9)>'
                payload2 = 'x'+attr_quote+' onmouseover=prompt(9) '+attr_quote
                payload3 = 'x'+attr_quote+'/onmouseover=prompt(9)/'+attr_quote
                try:
                    chars_payloads[chars].append(payload1)
                    chars_payloads[chars].append(payload2)
                    chars_payloads[chars].append(payload3)
                except KeyError:
                    chars_payloads[chars] = [payload1, payload2, payload3]

        # If no quotes are open or they're just not found:
        else:
            # means you can inject your own attribute value like:
            # x src=http://exploit.com
            if tag in ['script', 'frame', 'iframe']:
                chars = (':', ')', '(')
                payload = 'x src=JaVaSCript:prompt(9)'
                try:
                    chars_payloads[chars].append(payload)
                except KeyError:
                    chars_payloads[chars] = [payload]

            else:
                chars = ("<", ">")
                payload = 'x><svG onLoad=prompt(9)>'
                try:
                    chars_payloads[chars].append(payload)
                except KeyError:
                    chars_payloads[chars] = [payload]

        return chars_payloads

    def get_quote_context(self, line):
        """
        Goes through char by char to determine if double
        or single quotes are open or not: True/None
        """
        dquote_open = None
        squote_open = None
        # For something like <script>"hey":"hello's"</script> needed a way to remove the single quote
        # from being considered open since it's not actually important. This prevents a lot of false+
        # like in ebay.com and twitter.com
        first_open = None
        for c in line:
            if c == '"':
                # I have noticed that booking.com throws false+ with this first_open stuff
                if not first_open:
                    first_open = c
                dquote_open = self.opposite(dquote_open)
                if first_open == '"' and dquote_open == None:
                    first_open = None
                    if squote_open == True:
                        squote_open = None
            elif c == "'":
                if not first_open:
                    first_open = c
                squote_open = self.opposite(squote_open)
                if first_open == "'" and squote_open == None:
                    first_open = None
                    if dquote_open == True:
                        dquote_open = None

        return dquote_open, squote_open

    def opposite(self, obj):
        """Returns the obj as either True or None"""
        if obj:
            obj = None
        else:
            obj = True
        return obj

    def opposite_quote(self, quote):
        """
        Return the opposite quote of the one give, single for double or
        double for single.
        """
        if quote == '"':
            oppo_quote = "'"
        else:
            oppo_quote = '"'
        return oppo_quote

    def get_lxml_matches(
        self,
        full_match: str,
        body: str,
        resp_url: str,
        delim: str
    ):
        """Retrieve lxml injection matches from the response body."""
        sub = f"{delim}subbed"
        subbed_body = re.sub(full_match, sub, body)
        doc = self.html_parser(subbed_body, resp_url)
        lxml_injs = self.xpath_inj_points(sub, doc)
        return lxml_injs

    def html_parser(self, body: str, resp_url: str):
        """Parse the response body with lxml."""
        try:
            # You must use lxml.html.soupparser or else candyass webdevs who use identical
            # multiple html attributes with injections in them don't get caught
            # That being said, soupparser is crazy slow and introduces a ton of
            # new bugs so that is not an option at this point in time
            doc: html.etree._Element = html.fromstring(bytes(body, 'utf-8'), base_url=resp_url)
        except html.etree.ParserError:
            self.log('ParserError from lxml on %s' % resp_url)
            return
        except html.etree.XMLSyntaxError:
            self.log('XMLSyntaxError from lxml on %s' % resp_url)
            return
        return doc
        # try:
        #    # You must use soupparser or else candyass webdevs who use identical
        #    # multiple html attributes with injections in them don't get caught
        #    # EXCEPT I found out that soupparser is a CPU MONSTER and intros more bugs
        #    doc = lxml.html.soupparser.fromstring(subbed_body)
        # except ValueError:
        #    try:
        #        doc = lxml.html.fromstring(subbed_body)
        #    except lxml.etree.ParserError:
        #        self.log('ParserError from lxml on %s' % resp_url)
        #        return
        #    except lxml.etree.XMLSyntaxError:
        #        self.log('XMLSyntaxError from lxml on %s' % resp_url)
        #        return
        # except lxml.etree.ParserError:
        #    self.log('ParserError from lxml on %s' % resp_url)
        #    return
        # except lxml.etree.XMLSyntaxError:
        #    self.log('XMLSyntaxError from lxml on %s' % resp_url)
        #    return

    def combine_regex_lxml(
        self,
        lxml_injs: list,
        full_matches: list,
        body: str,
        mismatch: bool,
        payload: str,
        delim: str,
        spider: XSSspider
    ):
        """Combine lxml injection data with the 2 regex injection search data."""

        all_inj_data = {}

        for idx, match in enumerate(full_matches):
            try:
                tag_index, tag = lxml_injs[idx][0]
            except IndexError:
                if mismatch:
                    return
                else:
                    raise

            # Always returns a populated dict, even if its {None:None} like
            # with inbetween tag injections
            attrs_attrvals = lxml_injs[idx][1]
            if attrs_attrvals:
                for a in attrs_attrvals:
                    attr = a
                    attr_val = attrs_attrvals[a]
            # I don't think this is necessary now that we use lxml.html.soupparse.fromstring rather than lxml.html.fromstring
            else:
                spider.log(
                    "Error: Possible broken HTML. Lxml failed to find the attribute. twitter.com/?q=[payload] is an example.")
                continue
            # If it's an attribute inj then the tag will always be "<tag "
            # If it's an injection in a comment or between tags
            # it will always start with "<tag" (comment inj tag = "!--")
            if attr:
                tag_delim = '<'+tag+' '
            else:
                tag_delim = '<'+tag

            match_start_offset = match[0]
            ret_between_delim = match[1]
            match_end_offset = match[2]
            sub = delim+'subbed'

            start_of_match = body[match_start_offset:]
            ref_payload_plus_2 = start_of_match[:(
                match_end_offset - match_start_offset)+2]
            ref_payload = start_of_match[:(
                match_end_offset - match_start_offset)]
            # ref_payload would only equal ref_payload_plus_2 if ;9 doesn't exist
            if ref_payload != ref_payload_plus_2:
                if ref_payload_plus_2[-2:] == ';9':
                    ref_payload = ref_payload_plus_2

            # split the body at the tag, then take the last fragment
            # which is closest to the injection point as regexed
            split_body = body[:match_start_offset]
            # .replace('\\"', '').replace("\\'", "")
            line_no_tag = split_body.split(tag_delim)[-1]
            line = tag_delim + line_no_tag + ref_payload
            # Sometimes it may split wrong, in which case we drop that lxml match
            if line_no_tag.startswith('<doctype') or line_no_tag.startswith('<html'):
                line = ''

            # Get the accurate attr, as the original attr and attr_val in this function
            # would just be the first one found even if there were >1 attributes in lxml_injs
            if attr:
                attr_dict = self.accurate_attr(
                    tag, attrs_attrvals, match, line)
                for a in attr_dict:
                    attr = a
                    attr_val = attr_dict[a]
                    break

            unfiltered_chars = self.get_unfiltered_chars(
                payload, ref_payload, delim, tag, attr)
            # Common false+ shows only "> as unfiltered if script parses the chars between 2 unrelated delim strs
            # if unfiltered_chars == '">':
            #    unfiltered_chars = ''
            all_inj_data[match_start_offset] = [tag_index, tag,
                                                attr, attr_val, payload, unfiltered_chars, line]

        return all_inj_data

    def get_unfiltered_chars(self, payload: str, ref_payload: str, delim: str, tag: str, attr: str):
        """
        Pull out just the unfiltered chars from the reflected chars
        payload = delim+fuzz+delim+;9.
        """

        ref_chars = ref_payload.replace(delim, '').replace('9', '')
        fuzz_chars = payload.replace(delim, '').replace('9', '')
        remove_chars = set([])
        unfiltered_chars_list = []

        html_entities = ['&#39', '&quot;', '&lt;', '&gt;']
        # Remove html encoded entities
        for entity in html_entities:
            if entity in ref_chars:
                ref_chars.replace(entity, '')

        # If injection is inside script tag, remove the escaped chars
        if tag == 'script' or attr in self.event_attributes():
            ref_chars = ref_chars.replace("\\'", "").replace('\\"', '').replace(
                '\;', '').replace('\\>', '').replace('\\<', '').replace('\\/', '')

        for c in fuzz_chars:
            if c in ref_chars:
                continue
            else:
                remove_chars.add(c)

        for char in fuzz_chars:
            if char not in remove_chars:
                unfiltered_chars_list.append(char)

        unfiltered_chars = ''.join(unfiltered_chars_list)

        return unfiltered_chars

    def accurate_attr(self, tag: str, attrs_attrvals: dict, match: str, line: str):
        """
        lxml cannot determine the order of attrs which is important
        if we're using regex to find the location of the inj so this func
        finds the accurate attr based on the regex match amongst a list of
        attrs of the same tag. This is for multi injections in single attr_val
        as well as multi injections in multiple attrs.
        """

        # Going for process of elimination first
        copy_attrs_attrvals = attrs_attrvals.copy()
        for attr in attrs_attrvals:
            if attr+'=' not in line and attr+' =' not in line:
                copy_attrs_attrvals.pop(attr, None)

        # Keep doing research to find the accurate attr
        if len(copy_attrs_attrvals) > 1:
            attr_places = {}
            for attr in copy_attrs_attrvals:
                attrs_found = [x.end() for x in re.finditer(attr+'\s?=', line)]
                attr_places[max(attrs_found)] = attr
             # Get the attribute from the higher numbered key within attr_places
            closest_attr = attr_places[max(attr_places)]
            return {closest_attr: copy_attrs_attrvals[closest_attr]}

        # Found the accurate attr
        else:
            for attr in copy_attrs_attrvals:
                return {attr: copy_attrs_attrvals[attr]}

        return {None: None}

    def payloaded_lines(self, body: str, payload: str):
        """Finds and returns lines in the body that contain the specified payload."""
        return sorted([line for line in body.splitlines() if payload in line])

    def make_item(self, meta: dict, resp_url: str, line: str | list[str], unfiltered: str, sugg_payloads: list[str]):
        """Create the vulnerability item."""

        item = vuln()

        item['line'] = line if isinstance(line, str) else '\n'.join(line)
        item['xss_payload'] = meta['payload']
        item['unfiltered'] = unfiltered
        item['xss_param'] = meta['xss_param']
        item['xss_place'] = meta['xss_place']
        item['orig_url'] = meta['orig_url']
        item['resp_url'] = resp_url

        if sugg_payloads:
            item['sugg_payloads'] = ', '.join(sugg_payloads)
        if 'POST_to' in meta:
            item['POST_to'] = meta['POST_to']

        if item['unfiltered']:
            return item

    def xpath_inj_points(self, search_el: str, doc: html.etree._Element):
        """
        Searches the lxml document for any text, attributes, or comments
        that contain the specified search string.
        """

        injections = []
        same_tag_attrs = {}

        text_xss = doc.xpath(
            "//text()[contains(., $search_el)]",
            search_el=search_el
        )
        attr_xss = doc.xpath(
            "//*[@*[contains(., $search_el)]]",
            search_el=search_el
        )
        comment_xss = doc.xpath(
            "//comment()[contains(., $search_el)]",
            search_el=search_el
        )

        attr_inj = self.parse_attr_xpath(attr_xss, search_el, doc)
        comm_inj = self.parse_comm_xpath(comment_xss, search_el, doc)
        text_inj = self.parse_text_xpath(text_xss, search_el, doc)

        for inj_list in (attr_inj, comm_inj, text_inj):
            for inj in inj_list:
                tag_index, tag, attr, attr_val = inj

                # Sometimes <script> tags don't appear within the doc?? Dunno why, maybe some weird ajax shit
                # But if we remove them then we lose the matchups between lxml and regex so we must keep them
                # Just make them useless by entering empty tag and putting them at the end of the lxml matches
                # so a split at tag won't find anything
                if not tag_index:
                    print(
                        ' ' * 36 + 'ERROR: Could not find tag index location. Element does not exist in root doc.')
                    tag_index, tag = 999999999, ''

                loc_tag = (tag_index, tag)
                attr_attrval = {attr: attr_val} if attr else {}

                # combine the multi attr injections into a dict otherwise
                # just add the {attr, attr_val} injection as the second item
                if loc_tag in same_tag_attrs:
                    same_tag_attrs[loc_tag].update(attr_attrval)
                else:
                    same_tag_attrs[loc_tag] = attr_attrval

                injections.append((loc_tag, attr_attrval))

        # Final injections list should be like:
        # injections = [(tag_index, tag), {attribute1:attribute_value, attribute2:attribute_value}]
        # with variables amount of attributes with injected values
        injections = [(loc_tag, same_tag_attrs.get(loc_tag, {}))
                      for loc_tag, _ in injections]
        injections = sorted(injections)

        return sorted(injections)

    def get_elem_position(self, elem, doc):
        """
        Iterate through all elements in the document 
        and return the position of the specified element.
        """

        for order, i in enumerate(doc.iter(), start=1):
            if i is elem:
                return order

        return -1

    def parse_attr_xpath(self, xpath: list[html.etree._Element], search_str: str, doc: html.etree._Element):
        """Find all tags with attributes that contain the specified substring."""

        attr_inj = []

        for x in xpath:
            tag_index = self.get_elem_position(x, doc)

            for attr, attr_val in x.items():
                matches = re.findall(search_str, attr_val)
                for _ in matches:
                    attr_inj.append((tag_index, x.tag, attr, attr_val))

        return attr_inj

    def parse_comm_xpath(self, xpath: list[html.etree._Element], search_str: str, doc: html.etree._Element):
        """Parse the xpath comment search findings."""

        comm_inj = []

        for x in xpath:

            text = x.text or ''
            found_comments = re.findall(search_str, text)

            for _ in found_comments:
                tag_index = self.get_elem_position(x, doc)
                tag = '!--'
                comm_inj.append((tag_index, tag, None, None))

        return comm_inj

    def parse_text_xpath(self, xpath: list[html.etree._Element], search_str: str, doc: html.etree._Element):
        """Creates injection points for the xpath that finds the payload in any HTML enclosed text."""

        text_inj = []

        for x in xpath:
            parent: html.etree._Element = x.getparent()

            # In case parent is a Comment()
            while callable(parent.tag):
                parent = parent.getparent()

            tag_index = self.get_elem_position(parent, doc)
            found_texts = re.findall(search_str, x.strip())

            for _ in found_texts:
                text_inj.append((tag_index, parent.tag, None, None))

        return text_inj

    def unescape_payload(self, payload: str):
        """Unescape the various payload encodings (HTML and URL encodings)."""

        if '%' in payload:
            payload = unquote_plus(payload)

        payload = unescape(payload)

        return payload

    def get_reflected_chars(self, tag, attr, ref_payload: str, delim: str, body, match_end_offset):
        """
        Check for the special chars and append them to a master list of tuples, one tuple per injection point
        Always returns a string.
        """
        return ref_payload.replace(delim, '').replace('9', '')

    def url_item_filtering(self, item: dict):
        """Filter out duplicate XSS items based on the URL, parameter, payload, and unfiltered characters."""

        if item['xss_place'] != 'url':
            return item

        if not self.url_param_xss_items:
            self.url_param_xss_items.append(item)
            return item

        for i in self.url_param_xss_items:
            if (
                item['xss_param'] == i['xss_param'] and
                item['orig_url'].split('?', 1)[0] == i['orig_url'].split('?', 1)[0] and
                item['xss_payload'] == i['xss_payload'] and
                item['unfiltered'] == i['unfiltered']
            ):
                raise DropItem(f'Duplicate item found: {item["orig_url"]}')

        self.url_param_xss_items.append(item)
        return item

    def event_attributes(self):
        """HTML tag attributes that allow javascript TAKEN OUT AT THE MOMENT."""

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

    def write_to_file(self, item: dict, spider: XSSspider):
        """Writes the extracted item details to a specified file."""

        with open(self.filename, 'a+') as f:
            f.write('\n')

            log_messages = [
                f"URL: {item['orig_url']}",
                f"response URL: {item['resp_url']}",
                f"Unfiltered: {item['unfiltered']}",
                f"Payload: {item['xss_payload']}",
                f"Type: {item['xss_place']}",
                f"Injection point: {item['xss_param']}",
                f"Line: {item['line']}"
            ]

            if 'POST_to' in item:
                log_messages.append(f"POST url: {item['POST_to']}")
            if 'sugg_payloads' in item:
                log_messages.append(
                    f"Possible payloads: {item['sugg_payloads']}")
            if 'error' in item:
                log_messages.append(f"Error: {item['error']}")

            for message in log_messages:
                f.write(f"{message}\n")
                spider.log(f"    {message}", level=INFO)
