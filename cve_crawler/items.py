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


class CVEEntry(scrapy.Item):
    cve_id = scrapy.Field()                     # CVE编号
    vuln_status = scrapy.Field()                # 漏洞状态
    published_date = scrapy.Field()             # 发布日期
    last_modified = scrapy.Field()              # 最后修改日期
    description = scrapy.Field()                # 漏洞描述
    references = scrapy.Field()                 # 相关参考链接
    cwe_ids = scrapy.Field()                    # 关联的CWE编号
    affected_products = scrapy.Field()          # 影响范围
    cvss_v2_score = scrapy.Field()              # CVSS v2 基础分
    cvss_v2_vector = scrapy.Field()             # CVSS v2 向量字符串
    cvss_v2_severity = scrapy.Field()           # CVSS v2 严重等级
    cvss_v3_score = scrapy.Field()              # CVSS v3.1 基础分
    cvss_v3_vector = scrapy.Field()             # CVSS v3.1 向量字符串
    cvss_v3_severity = scrapy.Field()           # CVSS v3.1 严重等级
