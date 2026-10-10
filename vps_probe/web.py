"""前端页面：HTML、CSS、JavaScript 分文件维护，启动时拼成一个完整页面，不加载任何外部资源"""
import os

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
# 按顺序拼接到同一个作用域里：后面的文件可以使用前面定义的函数和变量
JS_FILES = ("core.js", "chart.js", "overview.js", "detail.js", "dialogs.js", "main.js")


def _read(name):
    with open(os.path.join(WEB_DIR, name), encoding="utf-8") as f:
        return f.read()


def build_page():
    js = "(function(){\n'use strict';\n" + "\n".join(_read(n) for n in JS_FILES) + "})();\n"
    html = _read("index.html")
    html = html.replace('<link rel="stylesheet" href="style.css">', "<style>\n" + _read("style.css") + "</style>")
    return html.replace('<script src="app.js"></script>', "<script>\n" + js + "</script>")
