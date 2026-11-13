from __future__ import annotations

import uuid
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone

from app import __version__
from app.models.db_models import Scan, Vulnerability


SEVERITY_XML = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
    "UNKNOWN": "unknown",
}


class SbomGenerator:
    def build(self, scan: Scan) -> dict:
        serial = _serial(scan)
        timestamp = _timestamp(scan)
        direct_refs = [dep.purl or _fallback_ref(dep) for dep in scan.dependencies if dep.direct]
        components = []
        for dep in scan.dependencies:
            component = {
                "type": "library",
                "bom-ref": dep.purl or _fallback_ref(dep),
                "name": dep.name,
                "version": dep.version or "unknown",
                "scope": "optional" if dep.scope.startswith("optional") else "required",
                "purl": dep.purl or _fallback_ref(dep),
                "properties": [
                    {"name": "dw:ecosystem", "value": dep.ecosystem},
                    {"name": "dw:dependency:type", "value": "direct" if dep.direct else "transitive"},
                    {"name": "dw:dependency:scope", "value": dep.scope},
                    {"name": "dw:inspection:status", "value": dep.inspection_status},
                    {"name": "dw:priority", "value": dep.priority_level},
                ],
            }
            if dep.license:
                component["licenses"] = [{"license": {"name": dep.license}}]
            components.append(component)

        vulnerabilities = _vulnerabilities(scan)
        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": serial,
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "author": "Dependency Watcher",
                            "name": "Dependency Watcher",
                            "version": __version__,
                        }
                    ]
                },
                "component": {
                    "type": "application",
                    "bom-ref": f"urn:dependency-watcher:scan:{scan.id}",
                    "name": scan.project_name,
                    "version": "1.0.0",
                },
                "properties": [
                    {"name": "dw:scan:id", "value": scan.id},
                    {"name": "dw:scan:source", "value": scan.source_type},
                    {"name": "dw:scan:security-score", "value": str(scan.security_score if scan.security_score is not None else "")},
                    {"name": "dw:scan:coverage-percent", "value": str(scan.coverage_percent)},
                ],
            },
            "components": components,
            "dependencies": [
                {
                    "ref": f"urn:dependency-watcher:scan:{scan.id}",
                    "dependsOn": direct_refs,
                }
            ],
        }
        if vulnerabilities:
            bom["vulnerabilities"] = vulnerabilities
        return bom

    def to_json(self, scan: Scan) -> str:
        import json

        return json.dumps(self.build(scan), indent=2, ensure_ascii=False)

    def to_xml(self, scan: Scan) -> str:
        bom = self.build(scan)
        namespace = "http://cyclonedx.org/schema/bom/1.5"
        ET.register_namespace("", namespace)

        def tag(name: str) -> str:
            return f"{{{namespace}}}{name}"

        root = ET.Element(tag("bom"))
        root.set("serialNumber", bom["serialNumber"])
        root.set("version", "1")
        root.set("bomFormat", "CycloneDX")
        root.set("specVersion", "1.5")

        metadata = ET.SubElement(root, tag("metadata"))
        ET.SubElement(metadata, tag("timestamp")).text = bom["metadata"]["timestamp"]
        tools = ET.SubElement(metadata, tag("tools"))
        tool_components = ET.SubElement(tools, tag("components"))
        tool = ET.SubElement(tool_components, tag("component"))
        tool.set("type", "application")
        ET.SubElement(tool, tag("author")).text = "Dependency Watcher"
        ET.SubElement(tool, tag("name")).text = "Dependency Watcher"
        ET.SubElement(tool, tag("version")).text = __version__
        meta_component = ET.SubElement(metadata, tag("component"))
        meta_component.set("type", "application")
        meta_component.set("bom-ref", bom["metadata"]["component"]["bom-ref"])
        ET.SubElement(meta_component, tag("name")).text = bom["metadata"]["component"]["name"]
        ET.SubElement(meta_component, tag("version")).text = "1.0.0"
        metadata_props = ET.SubElement(metadata, tag("properties"))
        for prop in bom["metadata"]["properties"]:
            node = ET.SubElement(metadata_props, tag("property"))
            node.set("name", prop["name"])
            node.text = prop["value"]

        components_node = ET.SubElement(root, tag("components"))
        for component in bom["components"]:
            node = ET.SubElement(components_node, tag("component"))
            node.set("type", "library")
            node.set("bom-ref", component["bom-ref"])
            ET.SubElement(node, tag("name")).text = component["name"]
            ET.SubElement(node, tag("version")).text = component["version"]
            ET.SubElement(node, tag("purl")).text = component["purl"]
            if component.get("licenses"):
                licenses = ET.SubElement(node, tag("licenses"))
                license_node = ET.SubElement(licenses, tag("license"))
                ET.SubElement(license_node, tag("name")).text = component["licenses"][0]["license"]["name"]
            properties = ET.SubElement(node, tag("properties"))
            for prop in component["properties"]:
                child = ET.SubElement(properties, tag("property"))
                child.set("name", prop["name"])
                child.text = prop["value"]

        dependencies_node = ET.SubElement(root, tag("dependencies"))
        for dependency in bom["dependencies"]:
            node = ET.SubElement(dependencies_node, tag("dependency"))
            node.set("ref", dependency["ref"])
            for ref in dependency["dependsOn"]:
                ET.SubElement(node, tag("dependency")).set("ref", ref)

        vulnerabilities = bom.get("vulnerabilities", [])
        if vulnerabilities:
            vuln_node = ET.SubElement(root, tag("vulnerabilities"))
            for vuln in vulnerabilities:
                node = ET.SubElement(vuln_node, tag("vulnerability"))
                node.set("bom-ref", vuln["bom-ref"])
                ET.SubElement(node, tag("id")).text = vuln["id"]
                source = ET.SubElement(node, tag("source"))
                ET.SubElement(source, tag("name")).text = vuln["source"]["name"]
                if vuln.get("description"):
                    ET.SubElement(node, tag("description")).text = vuln["description"]
                if vuln.get("detail"):
                    ET.SubElement(node, tag("detail")).text = vuln["detail"][:10000]
                if vuln.get("published"):
                    ET.SubElement(node, tag("published")).text = vuln["published"]
                if vuln.get("updated"):
                    ET.SubElement(node, tag("updated")).text = vuln["updated"]
                ratings = ET.SubElement(node, tag("ratings"))
                for rating in vuln.get("ratings", []):
                    rating_node = ET.SubElement(ratings, tag("rating"))
                    if rating.get("score") is not None:
                        ET.SubElement(rating_node, tag("score")).text = str(rating["score"])
                    ET.SubElement(rating_node, tag("severity")).text = rating["severity"]
                    ET.SubElement(rating_node, tag("method")).text = rating["method"]
                    if rating.get("vector"):
                        ET.SubElement(rating_node, tag("vector")).text = rating["vector"]
                affects = ET.SubElement(node, tag("affects"))
                for affected in vuln.get("affects", []):
                    affected_node = ET.SubElement(affects, tag("target"))
                    ET.SubElement(affected_node, tag("ref")).text = affected["ref"]
                    versions = ET.SubElement(affected_node, tag("versions"))
                    for version in affected.get("versions", []):
                        version_node = ET.SubElement(versions, tag("version"))
                        ET.SubElement(version_node, tag("version")).text = version["version"]
                        ET.SubElement(version_node, tag("status")).text = "affected"

        ET.indent(root, space="  ")
        return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")


def _vulnerabilities(scan: Scan) -> list[dict]:
    grouped: dict[str, list[Vulnerability]] = defaultdict(list)
    for vuln in scan.vulnerabilities:
        grouped[vuln.osv_id].append(vuln)
    output = []
    for osv_id, items in sorted(grouped.items()):
        first = items[0]
        rating = {
            "source": {"name": first.source or "OSV.dev"},
            "method": _cvss_method(first.cvss_version),
            "severity": SEVERITY_XML.get(first.severity, "unknown"),
        }
        if first.cvss_score is not None:
            rating["score"] = first.cvss_score
        if first.cvss_vector:
            rating["vector"] = first.cvss_vector
        output.append(
            {
                "bom-ref": f"vuln-{osv_id}",
                "id": osv_id,
                "source": {"name": first.source or "OSV.dev", "url": f"https://osv.dev/vulnerability/{osv_id}"},
                "references": [
                    {"id": alias, "source": {"name": "Alias"}}
                    for alias in (first.aliases or [])
                ],
                "ratings": [rating],
                "description": first.summary,
                "detail": first.details,
                "published": first.published or None,
                "updated": first.modified or None,
                "affects": [
                    {
                        "ref": item.dependency.purl if item.dependency else f"dependency-{item.dependency_id}",
                        "versions": [{"version": item.dependency.version if item.dependency else ""}],
                    }
                    for item in items
                ],
            }
        )
    return output


def _fallback_ref(dep) -> str:  # noqa: ANN001
    return f"pkg:generic/{dep.ecosystem}/{dep.name}@{dep.version or 'unknown'}"


def _cvss_method(version: str) -> str:
    if version.startswith("4"):
        return "CVSSv4"
    if version.startswith("3.1"):
        return "CVSSv31"
    if version.startswith("3"):
        return "CVSSv3"
    if version.startswith("2"):
        return "CVSSv2"
    return "other"


def _serial(scan: Scan) -> str:
    if scan.sbom_serial:
        try:
            return f"urn:uuid:{uuid.UUID(scan.sbom_serial)}"
        except ValueError:
            pass
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'dependency-watcher:{scan.id}')}"


def _timestamp(scan: Scan) -> str:
    value = scan.completed_at or scan.created_at or datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
