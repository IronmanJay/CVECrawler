#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""
@Project    ：CVECrawler
@File       ：settings.py
@Author     ：IronmanJay
@Date       ：2025/5/22 18:57
@Describe   ：配置文件
"""

# ================== 核心配置 ==================
BOT_NAME = 'CVECrawler'
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ResearchBot/1.0'        # 自定义UA标识
ROBOTSTXT_OBEY = False                                                          # API服务无需遵守robots协议
SPIDER_MODULES = ['cve_crawler.spiders']                                        # 强制启用爬虫自动发现

# ================== API认证与请求 ==================
import os
NVD_API_KEY = os.getenv('NVD_API_KEY', '237ebc79-0fb8-450b-8062-68ceaa80ba00')  # 优先读取环境变量
DOWNLOAD_DELAY = 6                                                              # 基础请求间隔（配合NVD 50请求/分钟限制）
CONCURRENT_REQUESTS = 2                                                         # 平衡速率限制与性能
AUTOTHROTTLE_ENABLED = True                                                     # 智能动态限速
DEFAULT_REQUEST_HEADERS = {
    'Accept': 'application/json',
    'Authorization': f'Bearer {NVD_API_KEY}'                                    # 统一使用新版Bearer认证
}

# ================== 数据输出 ==================
FEED_FORMAT = 'json'                                                            # 输出格式
FEED_URI = 'cve_data_%(time)s.json'                                             # 带时间戳防覆盖
FEED_EXPORT_ENCODING = 'utf-8'                                                  # 避免中文乱码
FEED_EXPORT_INDENT = 2                                                          # 美化JSON格式

# ================== 错误处理 ==================
RETRY_TIMES = 3                                                                 # 失败请求重试次数
RETRY_HTTP_CODES = [429, 500, 502, 503]                                         # 仅重试可恢复错误

# ================== 日志优化 ==================
LOG_LEVEL = 'INFO'                                                              # 生产级日志输出
LOG_FORMAT = '%(asctime)s [%(name)s] %(levelname)s: %(message)s'
LOG_DATEFORMAT = '%Y-%m-%d %H:%M:%S'

# ================== 性能优化 ==================
AUTOTHROTTLE_TARGET_CONCURRENCY = 2.0                                           # 目标并发数
DOWNLOAD_TIMEOUT = 30                                                           # 延长超时应对NVD高延迟
HTTPCACHE_ENABLED = True                                                        # 启用缓存提升性能
HTTPCACHE_EXPIRATION_SECS = 86400                                               # 24小时缓存有效期

# ================== 安全配置 ==================
COOKIES_ENABLED = False                                                         # 禁用Cookie节省资源
DOWNLOAD_MAXSIZE = 10 * 1024 * 1024                                             # 限制10MB响应体
