#!/bin/bash
cd /usr/share/xsscrapy;
if [ $# -le 0 ]; then
    /usr/bin/scrapy crawl xsscrapy --help;
else
    /usr/bin/scrapy crawl xsscrapy "$@";
fi
