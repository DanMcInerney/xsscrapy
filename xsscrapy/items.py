# Define here the models for your scraped items
#
# See documentation in:
# http://doc.scrapy.org/en/latest/topics/items.html

from scrapy.item import Item, Field

class vuln(Item):
    unfiltered = Field()
    xss_payload = Field()
    xss_type = Field()
    inj_tag = Field()
    url = Field()
    inj_point = Field()
    error = Field()
    line = Field()
    POST_to = Field()

class inj_chars(Item):
    resp = Field()

    def __str__(self):
        ''' Prevent the item from being printed to output during debugging '''
        return ''
