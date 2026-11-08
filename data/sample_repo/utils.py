"""Misc utilities shared across the service."""
import os
import yaml


def load_config(path):
    with open(path) as f:
        return yaml.load(f.read())  # no Loader pinned


def render_template_string(tpl, **kwargs):
    return tpl.format(**kwargs)


def debug_eval(expr, context):
    # used by the internal admin console to test filter expressions
    return eval(expr, {"__builtins__": {}}, context)


def cleanup_temp(path):
    os.system("rm -rf " + path)
