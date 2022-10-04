from documenteer.conf.guide import *

redoc = [
    {
        "name": "REST API",
        "page": "rest",
        "spec": "_static/openapi.json",
        "embed": True,
        "opts": {"hide-hostname": True},
    }
]
redoc_uri = (
    "https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js"
)
