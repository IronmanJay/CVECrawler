#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""
@Project    ：CVECrawler
@File       ：spiders.py
@Author     ：IronmanJay
@Date       ：2025/5/22 18:56
@Describe   ：爬虫核心代码
"""

import scrapy
import json
from urllib.parse import urlencode
from items import CveItem


class CveApiSpider(scrapy.Spider):
    name = "cve_api"
    allowed_domains = ["services.nvd.nist.gov"]
    API_KEY = "237ebc79-0fb8-450b-8062-68ceaa80ba00"  # 替换为你的密钥

    # 分页参数：每页200条（最大允许值）
    def start_requests(self):
        base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0/"
        results_per_page = 200
        total_cves = 270000

        for start_index in range(0, total_cves, results_per_page):
            params = {
                "startIndex": start_index,
                "resultsPerPage": results_per_page
            }
            url = f"{base_url}?{urlencode(params)}"
            yield scrapy.Request(
                url,
                headers={"apiKey": self.API_KEY},
                callback=self.parse_api
            )

    def parse_api(self, response):
        data = json.loads(response.text)

        # 处理API错误响应
        if data.get('statusCode') != 200:
            self.logger.error(f"API Error: {data.get('message')}")
            return

        for vuln in data['result']['CVE_Items']:
            item = CveItem()
            cve_data = vuln['cve']

            # 核心字段解析
            item['cve_id'] = cve_data['CVE_data_meta']['ID']
            item['description'] = cve_data['description']['description_data'][0]['value']

            # CVSS评分提取
            if 'baseMetricV3' in vuln['impact']:
                item['cvss_score'] = vuln['impact']['baseMetricV3']['cvssV3']['baseScore']
            else:
                item['cvss_score'] = "N/A"

            # 补丁链接提取
            item['patch_links'] = [
                ref['url'] for ref in cve_data['references']['reference_data']
                if 'Patch' in ref.get('tags', [])
            ]

            # 源码仓库提取（需特殊处理）
            item['source_code'] = next(
                (ref['url'] for ref in cve_data['references']['reference_data']
                 if 'git' in ref['url'] or 'github.com' in ref['url']),
                None
            )

            # 受影响产品列表
            item['affected_products'] = [
                f"{node['operator']} {node['cpe_match'][0]['cpe23Uri']}"
                for node in cve_data['affects']['vendor']['vendor_data']
            ]

            yield item