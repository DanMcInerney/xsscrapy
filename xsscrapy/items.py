# Define here the models for your scraped items
#
# See documentation in:
# http://doc.scrapy.org/en/latest/topics/items.html

from scrapy.item import Item, Field

class URL(Item):
    vuln_url = Field()
    high = Field()
    medium = Field()
    low = Field()
    error = Field()
