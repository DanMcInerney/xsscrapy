# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: http://doc.scrapy.org/en/latest/topics/item-pipeline.html
from scrapy.exceptions import DropItem

class XSS_pipeline(object):
    ''' Prevent some duplicate url param injection items with process_item
        Duplicate forms are already prevented in the spider with self.form_requests_made
        Duplicate header injection is prevented with middleware that prevents duplicate URLs
        from being crawled '''

    def __init__(self):
        self.url_param_xss_items = []

    def process_item(self, item, spider):
        ''' Prevent some duplicate url param injection items
            We already prevent duplicate form data from being sent inside
            the spider with self.form_requests_made = set()
            Scared of false negatives so this is a purposely weak filter'''

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

        self.write_to_file(item)

        return item

    def write_to_file(self, item):
        with open('formatted-vulns.txt', 'a+') as f:
            f.write('\n')
            if 'error' in item:
                f.write('Error: '+item['error']+'\n')
            if 'POST_to' in item:
                f.write('POST url: '+item['POST_to']+'\n')
            f.write('URL: '+item['url']+'\n')
            f.write('Unfiltered: '+item['unfiltered']+'\n')
            f.write('Payload: '+item['xss_payload']+'\n')
            f.write('Type: '+item['xss_type']+'\n')
            f.write('Injection point: '+item['inj_point']+'\n')
            for line in item['line']:
                f.write('Line: '+line[1]+'\n')
