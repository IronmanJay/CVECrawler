#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""
@Project    ：CVECrawler
@File       ：__init__.py
@Author     ：IronmanJay
@Date       ：2025/5/28 11:01
@Describe   ：模块级标识及初始化
"""

import sys
from .spiders import spiders

__all__ = ['spiders']                           # 控制可访问的爬虫类

if sys.version_info < (3, 8):                   # 强制Python版本检查
    sys.exit("Scrapy requires Python 3.8+")
