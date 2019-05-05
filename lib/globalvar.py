# -*- coding: utf-8 -*-

# 作者：咚咚呛
# 全局参数管理模块

def init():
    global _global_dict
    _global_dict = {}


def set_value(name, value):
    _global_dict[name] = value


def get_value(name, defValue=None):
    try:
        return _global_dict[name]
    except KeyError:
        return defValue
