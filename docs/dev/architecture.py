"""Source for architecture.png, the architecture diagram."""

from diagrams import Cluster
from diagrams.gcp.compute import KubernetesEngine
from diagrams.gcp.database import SQL
from diagrams.gcp.network import LoadBalancing
from diagrams.gcp.storage import PersistentDisk
from diagrams.k8s.compute import Cronjob
from diagrams.onprem.client import User
from diagrams.onprem.compute import Server
from diagrams.programming.framework import React
from sphinx_diagrams import SphinxDiagram

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

with SphinxDiagram(
    title="Gafaelfawr deployment architecture",
    graph_attr=graph_attr,
    node_attr=node_attr,
):
    user = User("End user")
    database = SQL("Database")

    with Cluster("Kubernetes"):
        ingress = LoadBalancing("NGINX ingress")
        ui = React("Squareone")

        with Cluster("Gafaelfawr"):
            server = KubernetesEngine("Server")
            redis = KubernetesEngine("Redis")
            storage = PersistentDisk("Redis storage")
            operator = KubernetesEngine("Kubernetes operator")
            maintenance = Cronjob("Maintenance")

            user >> ingress >> ui >> server >> redis >> storage
            ingress >> server >> database
            operator >> redis >> storage
            operator >> database
            maintenance >> redis >> storage
            maintenance >> database

        app = KubernetesEngine("Application")

        ingress >> app

    idp = Server("Identity provider")

    server >> idp
    user >> idp
