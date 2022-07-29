"""Source for architecture.png, the architecture diagram."""

import os

from diagrams import Cluster, Diagram
from diagrams.gcp.compute import KubernetesEngine
from diagrams.gcp.network import LoadBalancing
from diagrams.gcp.storage import PersistentDisk
from diagrams.onprem.client import User
from diagrams.onprem.compute import Server

os.chdir(os.path.dirname(__file__))

graph_attr = {
    "label": "",
    "nodesep": "0.2",
    "pad": "0.2",
    "ranksep": "0.75",
    "splines": "spline",
}

node_attr = {
    "fontsize": "12.0",
}

with Diagram(
    "Gafaelfawr",
    show=False,
    filename="architecture",
    outformat="png",
    graph_attr=graph_attr,
    node_attr=node_attr,
):
    user = User("End user")

    with Cluster("Kubernetes"):
        ingress = LoadBalancing("NGINX ingress")

        with Cluster("Gafaelfawr"):
            server = KubernetesEngine("Server")
            redis = KubernetesEngine("Redis")
            storage = PersistentDisk("Redis storage")
            KubernetesEngine("Kubernetes operator")

            user >> ingress >> server >> redis >> storage

        app = KubernetesEngine("Application")

        ingress >> app

    idp = Server("Identity provider")

    server >> idp
    user >> idp
