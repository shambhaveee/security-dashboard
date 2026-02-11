import json
import csv
import os

# ---------- SONARQUBE ----------
sonar_rows = []

for file in os.listdir("sonarqube_json"):
    with open(os.path.join("sonarqube_json", file)) as f:
        data = json.load(f)
        sonar_rows.append([
            data["project"],
            data["measures"]["vulnerabilities"]["critical"],
            data["measures"]["vulnerabilities"]["high"],
            data["analysisDate"]
        ])

with open("sonarqube.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["product", "code_critical", "code_high", "sonar_scan"])
    writer.writerows(sonar_rows)

# ---------- BLACK DUCK ----------
bd_rows = []

for file in os.listdir("blackduck_json"):
    with open(os.path.join("blackduck_json", file)) as f:
        data = json.load(f)
        bd_rows.append([
            data["projectName"],
            data["riskProfile"]["vulnerabilityRisk"]["critical"],
            data["riskProfile"]["vulnerabilityRisk"]["high"],
            data["riskProfile"]["licenseRisk"],
            data["scanDate"]
        ])

with open("blackduck.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["product", "dependency_critical", "dependency_high", "license_risk", "bd_scan"])
    writer.writerows(bd_rows)

# ---------- UNIFIED ----------
sonar = {row[0]: row for row in sonar_rows}
blackduck = {row[0]: row for row in bd_rows}

with open("unified.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "product",
        "code_critical",
        "code_high",
        "dependency_critical",
        "dependency_high",
        "license_risk",
        "last_scan"
    ])

    for product in sonar:
        s = sonar[product]
        b = blackduck[product]

        writer.writerow([
            product,
            s[1],
            s[2],
            b[1],
            b[2],
            b[3],
            max(s[3], b[4])
        ])
