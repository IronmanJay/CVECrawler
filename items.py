#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""
@Project    ：CVECrawler
@File       ：items.py
@Author     ：IronmanJay
@Date       ：2025/5/22 18:57
@Describe   ：定义爬虫抓取数据结构
"""

import scrapy


class CveItem(scrapy.Item):
    cve_id = scrapy.Field()
    description = scrapy.Field()
    cvss_score = scrapy.Field()
    patch_links = scrapy.Field()
    source_code = scrapy.Field()
    affected_products = scrapy.Field()
