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
from dateutil.parser import parse
from cve_crawler.items import CVEEntry
from urllib.parse import quote


class NvdApiSpider(scrapy.Spider):
    """
    CVE信息采集
    """
    name = 'nvd_spider'                                                 # Scrapy框架使用的唯一爬虫ID
    allowed_domains = ['services.nvd.nist.gov']                         # 限制爬取域名
    results_per_page = 2000                                             # 每页请求数量（NVD API单次最大允许值）
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"       # API v2端点
    params = {
        'startIndex': 0,                                                # 分页起始索引
        'resultsPerPage': results_per_page,                             # 每页结果数
        'noRejected': None                                              # 过滤被拒绝的CVE记录
    }

    def start_requests(self):
        """
        初始化API请求
        :return: 解析回调函数
        """
        url = self.build_api_url()
        yield scrapy.Request(
            url,
            headers={'apiKey': self.settings.get('NVD_API_KEY')},
            callback=self.parse
        )

    def build_api_url(self):
        """
        动态构建API请求URL
        :return: API请求URL
        """
        params = []

        # 处理分页参数
        params.append(f"startIndex={self.params['startIndex']}")
        params.append(f"resultsPerPage={self.params['resultsPerPage']}")

        # 过滤参数
        if self.params.get('noRejected'):
            params.append("noRejected")

        # 关键词搜索处理
        if hasattr(self, 'keyword_search'):
            encoded_keyword = quote(self.keyword_search)
            params.append(f"keywordSearch={encoded_keyword}")
            # 精确匹配模式
            if hasattr(self, 'keyword_exact_match'):
                params.append("keywordExactMatch")
        return f"{self.base_url}?{'&'.join(params)}"

    def parse(self, response):
        """
        API响应主解析器
        :param response: API响应
        :return: 下一页请求
        """
        try:
            data = response.json()
        except ValueError as e:
            self.logger.error(f"JSON解析失败: {e}")
            return

        # 分页状态跟踪
        total_results = data.get('totalResults', 0)
        self.logger.info(f"当前进度: {self.params['startIndex']}/{total_results}")

        # 解析漏洞条目
        for vuln in data.get('vulnerabilities', []):
            yield self.parse_cve(vuln['cve'])

        # 分页请求生成
        if self.params['startIndex'] + self.results_per_page < total_results:
            self.params['startIndex'] += self.results_per_page
            yield scrapy.Request(
                self.build_api_url(),
                headers={'apiKey': self.settings.get('NVD_API_KEY')},
                callback=self.parse
            )

    def parse_cve(self, cve_data):
        """
        单个CVE条目解析器
        :param cve_data: 单个CVE数据
        :return: 解析好的CVE数据
        """
        item = CVEEntry()

        # 基础信息
        item['cve_id'] = cve_data.get('id', '')
        item['published_date'] = parse(cve_data.get('published', '')).isoformat()
        item['last_modified'] = parse(cve_data.get('lastModified', '')).isoformat()
        item['vuln_status'] = cve_data.get('vulnStatus', '')

        # 描述信息
        item['description'] = next((
            desc['value'] for desc in cve_data.get('descriptions', [])
            if desc.get('lang') == 'en'
        ), '')

        # CVSS评分信息
        self.parse_metrics(cve_data.get('metrics', {}), item)

        # 参考链接
        references = cve_data.get('references', [])
        item['references'] = [
            {
                'url': ref.get('url'),
                'tags': ref.get('tags', [])
            } for ref in references
        ]

        # CWE信息
        if weaknesses := cve_data.get('weaknesses'):
            item['cwe_ids'] = [
                weakness.get('description', [{}])[0].get('value')
                for weakness in weaknesses
            ]

        # 影响范围信息
        if configurations := cve_data.get('configurations'):
            item['affected_products'] = self.get_affected_products(configurations)

        return item

    @staticmethod
    def parse_metrics(metrics_data, item):
        """
        CVSS评分系统解析
        :param metrics_data: 评分数据
        :param item: 待添加的字典
        :return: 解析好的数据
        """
        # CVSS v2数据处理
        if 'cvssMetricV2' in metrics_data:
            cvss_v2 = metrics_data['cvssMetricV2'][0]['cvssData']
            item['cvss_v2_score'] = cvss_v2.get('baseScore')
            item['cvss_v2_vector'] = cvss_v2.get('vectorString')
            item['cvss_v2_severity'] = metrics_data['cvssMetricV2'][0].get('baseSeverity')

        # CVSS v3.1数据处理
        if 'cvssMetricV31' in metrics_data:
            cvss_v31 = metrics_data['cvssMetricV31'][0]['cvssData']
            item['cvss_v3_score'] = cvss_v31.get('baseScore')
            item['cvss_v3_vector'] = cvss_v31.get('vectorString')
            item['cvss_v3_severity'] = metrics_data['cvssMetricV31'][0].get('baseSeverity')

    @staticmethod
    def get_affected_products(configurations):
        """
        影响范围
        :param configurations: 相关数据
        :return: 解析好的数据，包含影响范围信息
        """
        products = set()
        for config in configurations:
            for node in config.get('nodes', []):
                for match in node.get('cpeMatch', []):
                    if criteria := match.get('criteria', ''):
                        parts = criteria.split(':')
                        # 提取CPE格式中的厂商和产品字段
                        if len(parts) >= 5:
                            products.add(f"{parts[3]}:{parts[4]}")
        return list(products)
