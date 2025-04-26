import requests
import json
import urllib.parse
import whois
import socket
from bs4 import BeautifulSoup

def load_config(config_file='config.json'):
    with open(config_file, 'r') as file:
        return json.load(file)

APIs_Keys = load_config()

def safe_api_call(api_name, method, url, headers=None, params=None, data=None, json_payload=None, timeout=15):
    try:
        if method.lower() == "get":
            response = requests.get(url, headers=headers, params=params, timeout=timeout)
        else:
            if json_payload is not None:
                response = requests.post(url, headers=headers, json=json_payload, timeout=timeout)
            else:
                response = requests.post(url, headers=headers, data=data, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.Timeout:
        return {"error": f"=== {api_name} ===\nError: The request timed out."}
    except requests.exceptions.RequestException as e:
        return {"error": f"=== {api_name} ===\nError: An error occurred: {e}"}

def abuseipdb_ip(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip, 'maxAgeInDays': '360'}
    headers = {'Accept': 'application/json', 'Key': APIs_Keys['abuseipdb_key']}
    result = safe_api_call("AbuseIPDB", "GET", url, headers=headers, params=params)
    if "error" in result:
        return result["error"]
    data = result.get("data")
    if data:
        host_names = ', '.join(data.get("hostnames", []))
        return (
            f"=== AbuseIPDB ===\n"
            f"Abuse Confidence Score: %{data.get('abuseConfidenceScore')}\n"
            f"Country Code: {data.get('countryCode')}\n"
            f"Domain: {data.get('domain')}\n"
            f"Host Names: {host_names}\n"
            f"IP Address: {data.get('ipAddress')}\n"
            f"ISP: {data.get('isp')}\n"
            f"Usage Type: {data.get('usageType')}\n"
            f"Last Report: {data.get('lastReportedAt')}\n"
            f"Total Reports: {data.get('totalReports')}\n"
        )
    else:
        return "=== AbuseIPDB ===\nError: 'data' key not found in the response."

def virustotal_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"accept": "application/json", "x-apikey": APIs_Keys['virus_total_key']}
    result = safe_api_call("VirusTotal", "GET", url, headers=headers, timeout=30)
    if "error" in result:
        return result["error"]
    data = result.get("data")
    if data:
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        stats_str = ', '.join(f"{k}: {v}" for k, v in stats.items())
        reputation = attributes.get("reputation", "N/A")
        return (
            f"=== VirusTotal ===\n"
            f"Security Vendors Analysis: {stats_str}\n"
            f"Reputation: {reputation}\n"
        )
    else:
        return "=== VirusTotal ===\nError: 'data' key not found in the response."

def threatfox_ip(ip):
    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {"accept": "application/json", "Auth-Key": APIs_Keys['abuse_ch_key']}
    payload = {"query": "search_ioc", "search_term": ip}
    result = safe_api_call("ThreatFox", "POST", url, headers=headers, json_payload=payload, timeout=15)
    if "error" in result:
        return result["error"]
    if result.get("query_status") == "no_result":
        return "=== ThreatFox ===\nError: Your search did not yield any results."
    data = result.get("data")
    if isinstance(data, list):
        unique = set()
        fields = {
            "confidence_levels": [],
            "threat_types": [],
            "threat_type_descs": [],
            "first_seens": [],
            "last_seens": [],
            "malware_printables": []
        }
        for item in data:
            key = (item.get("confidence_level"), item.get("threat_type"), item.get("threat_type_desc"), item.get("first_seen"), item.get("last_seen"), item.get("malware_printable"))
            if key not in unique:
                unique.add(key)
                fields["confidence_levels"].append(item.get("confidence_level", "N/A"))
                fields["threat_types"].append(item.get("threat_type", "N/A"))
                fields["threat_type_descs"].append(item.get("threat_type_desc", "N/A"))
                fields["first_seens"].append(item.get("first_seen") or "N/A")
                fields["last_seens"].append(item.get("last_seen") or "N/A")
                fields["malware_printables"].append(item.get("malware_printable", "N/A"))
        return (
            f"=== ThreatFox ===\n"
            f"Confidence Levels: {', '.join(map(str, fields['confidence_levels']))}\n"
            f"Threat Types: {', '.join(fields['threat_types'])}\n"
            f"Threat Type Descriptions: {', '.join(fields['threat_type_descs'])}\n"
            f"First Seen: {', '.join(fields['first_seens'])}\n"
            f"Last Seen: {', '.join(fields['last_seens'])}\n"
            f"Malware Printable: {', '.join(fields['malware_printables'])}\n"
        )
    else:
        return "=== ThreatFox ===\nError: 'data' key not found in the response."

def urlhaus_url(url_to_query):
    url = "https://urlhaus-api.abuse.ch/v1/url/"
    headers = {"accept": "application/json"}
    payload = {"url": url_to_query}
    result = safe_api_call("URLhaus", "POST", url, headers=headers, data=payload, timeout=15)
    if "error" in result:
        return result["error"]
    status = result.get("query_status")
    if status == "no_results":
        return "=== URLhaus ===\nError: Your search did not yield any results."
    elif status == "ok":
        return (
            f"=== URLhaus ===\n"
            f"URL Status: {result.get('url_status', 'N/A')}\n"
            f"Host: {result.get('host', 'N/A')}\n"
            f"Date Added: {result.get('date_added', 'N/A')}\n"
            f"Last Online: {result.get('last_online', 'N/A')}\n"
            f"Threat: {result.get('threat', 'N/A')}\n"
            f"Tags: {', '.join(result.get('tags', []))}\n"
        )
    else:
        return "=== URLhaus ===\nError: Unexpected query status."

def ipqualityscore_url(url_to_query):
    encoded = urllib.parse.quote(url_to_query, safe="")
    url = f"https://www.ipqualityscore.com/api/json/url/{APIs_Keys['ipqualityscore_key']}/{encoded}"
    result = safe_api_call("IPQualityScore", "POST", url, timeout=15)
    if "error" in result:
        return result["error"]
    if not result.get("success"):
        return "=== IPQualityScore ===\nError: Unsuccessful API response."
    required_fields = {
        "Domain": result.get("domain"),
        "Server": result.get("server"),
        "Dns Valid": result.get("dns_valid"),
        "Parking": result.get("parking"),
        "Spamming": result.get("spamming"),
        "Malware": result.get("malware"),
        "Phishing": result.get("phishing"),
        "Suspicious": result.get("suspicious"),
        "Risk Score": result.get("risk_score"),
        "Country Code": result.get("country_code"),
        "Category": result.get("category")
    }
    return "=== IPQualityScore ===\n" + "\n".join(f"{k}: {v}" for k, v in required_fields.items())

def virustotal_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"accept": "application/json", "x-apikey": APIs_Keys['virus_total_key']}
    result = safe_api_call("VirusTotal", "GET", url, headers=headers, timeout=30)
    if "error" in result:
        return result["error"]
    data = result.get("data")
    if data:
        attributes = data.get("attributes", {})
        stats_str = ', '.join(f"{k}: {v}" for k, v in attributes.get("last_analysis_stats", {}).items())
        return (
            f"=== VirusTotal ===\n"
            f"ID: {data.get('id', 'N/A')}\n"
            f"Type: {data.get('type', 'N/A')}\n"
            f"TLD: {attributes.get('tld', 'N/A')}\n"
            f"Registrar: {attributes.get('registrar', 'N/A')}\n"
            f"Security Vendors Analysis: {stats_str}\n"
        )
    else:
        return "=== VirusTotal ===\nError: 'data' key not found in the response."

def threatfox_domain(domain):
    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {"accept": "application/json", "Auth-Key": APIs_Keys['abuse_ch_key']}
    payload = {"query": "search_ioc", "search_term": domain}
    result = safe_api_call("ThreatFox", "POST", url, headers=headers, json_payload=payload, timeout=15)
    if "error" in result:
        return result["error"]
    if result.get("query_status") == "no_result":
        return "=== ThreatFox ===\nError: Your search did not yield any results."
    data = result.get("data")
    if isinstance(data, list):
        for item in data:
            if item.get("ioc_type") == "domain":
                return (
                    f"=== ThreatFox ===\n"
                    f"IOC: {item.get('ioc', 'N/A')}\n"
                    f"IOC Type: {item.get('ioc_type', 'N/A')}\n"
                    f"Malware Printable: {item.get('malware_printable', 'N/A')}\n"
                    f"Threat Type Description: {item.get('threat_type_desc', 'N/A')}\n"
                    f"Confidence Level: {item.get('confidence_level', 'N/A')}\n"
                    f"First Seen: {item.get('first_seen', 'N/A')}\n"
                    f"Last Seen: {item.get('last_seen', 'N/A')}\n"
                    f"Tags: {' '.join(item.get('tags', []))}\n"
                )
        return "=== ThreatFox ===\nError: No domain IOC found."
    else:
        return "=== ThreatFox ===\nError: 'data' key not found in the response."

def ipqualityscore_domain(domain):
    encoded = urllib.parse.quote(domain, safe="")
    url = f"https://www.ipqualityscore.com/api/json/url/{APIs_Keys['ipqualityscore_key']}/{encoded}"
    result = safe_api_call("IPQualityScore", "POST", url, timeout=15)
    if "error" in result:
        return result["error"]
    if not result.get("success"):
        return "=== IPQualityScore ===\nError: Unsuccessful API response."
    required_fields = {
        "Domain": result.get("domain"),
        "Server": result.get("server"),
        "Dns Valid": result.get("dns_valid"),
        "Parking": result.get("parking"),
        "Spamming": result.get("spamming"),
        "Malware": result.get("malware"),
        "Phishing": result.get("phishing"),
        "Suspicious": result.get("suspicious"),
        "Risk Score": result.get("risk_score"),
        "Country Code": result.get("country_code"),
        "Category": result.get("category")
    }
    return "=== IPQualityScore ===\n" + "\n".join(f"{k}: {v}" for k, v in required_fields.items())

def virustotal_hash(file_value):
    url = f"https://www.virustotal.com/api/v3/files/{file_value}"
    headers = {"accept": "application/json", "x-apikey": APIs_Keys['virus_total_key']}
    result = safe_api_call("VirusTotal", "GET", url, headers=headers, timeout=30)
    if "error" in result:
        return result["error"]
    data = result.get("data")
    if data:
        attributes = data.get("attributes", {})
        tags = ', '.join(attributes.get("tags", []))
        stats_str = ', '.join(f"{k}: {v}" for k, v in attributes.get("last_analysis_stats", {}).items())
        suggested = attributes.get("popular_threat_classification", {}).get("suggested_threat_label", "N/A")
        return (
            f"=== VirusTotal ===\n"
            f"ID: {data.get('id', 'N/A')}\n"
            f"Tags: {tags}\n"
            f"Type Extension: {attributes.get('type_extension', 'N/A')}\n"
            f"Names: {', '.join(attributes.get('names', []))}\n"
            f"Last Analysis Stats: {stats_str}\n"
            f"Suggested Threat Label: {suggested}\n"
        )
    else:
        return "=== VirusTotal ===\nError: 'data' key not found in the response."

def malwarebazaar_hash(hash_value):
    url = "https://mb-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": APIs_Keys['abuse_ch_key']}
    data_payload = {"query": "get_info", "hash": hash_value}
    result = safe_api_call("MalwareBazaar", "POST", url, headers=headers, data=data_payload, timeout=15)
    if "error" in result:
        return result["error"]
    if result.get("query_status") == "ok" and result.get("data"):
        item = result["data"][0]
        tags = ', '.join(item.get("tags", []))
        fields = {
            "sha256": item.get("sha256_hash", "N/A"),
            "sha1": item.get("sha1_hash", "N/A"),
            "md5": item.get("md5_hash", "N/A"),
            "First Seen": item.get("first_seen", "N/A"),
            "Last Seen": item.get("last_seen", "N/A"),
            "File Name": item.get("file_name", "N/A"),
            "File Type": item.get("file_type", "N/A"),
            "Delivery Method": item.get("delivery_method", "N/A"),
            "Tags": tags,
            "Origin Country": item.get("origin_country", "N/A"),
            "YOROI YOMI Detection": item.get("vendor_intel", {}).get("YOROI_YOMI", {}).get("detection", "N/A"),
            "YOROI YOMI Score": item.get("vendor_intel", {}).get("YOROI_YOMI", {}).get("score", "N/A"),
            "Intezer Verdict": item.get("vendor_intel", {}).get("Intezer", {}).get("verdict", "N/A"),
            "InQuest Verdict": item.get("vendor_intel", {}).get("InQuest", {}).get("verdict", "N/A"),
            "Triage Score": item.get("vendor_intel", {}).get("Triage", {}).get("score", "N/A"),
            "ReversingLabs Threat Name": item.get("vendor_intel", {}).get("ReversingLabs", {}).get("threat_name", "N/A"),
            "ReversingLabs Status": item.get("vendor_intel", {}).get("ReversingLabs", {}).get("status", "N/A"),
            "Spamhaus HBL Detection": item.get("vendor_intel", {}).get("Spamhaus_HBL", [{}])[0].get("detection", "N/A"),
            "FileScan-IO Verdict": item.get("vendor_intel", {}).get("FileScan-IO", {}).get("verdict", "N/A")
        }
        return "=== MalwareBazaar ===\n" + "\n".join(f"{k}: {v}" for k, v in fields.items())
    else:
        return "=== MalwareBazaar ===\nNo data available" if result.get("query_status") == "ok" else "=== MalwareBazaar ===\nError: Unexpected query status."

def hybrid_analysis_hash(hash_value):
    url = 'https://www.hybrid-analysis.com/api/v2/search/hash'
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
        'api-key': APIs_Keys['hybrid_analysis_key']
    }
    data_payload = {'hash': hash_value}
    result = safe_api_call("Hybrid Analysis", "POST", url, headers=headers, data=data_payload)
    if "error" in result:
        return result["error"]
    formatted = []
    for res in result:
        formatted.append(
            f"\n=== Hybrid Analysis ===\n"
            f"sha256: {res.get('sha256')}\n"
            f"sha1: {res.get('sha1')}\n"
            f"md5: {res.get('md5')}\n"
            f"av_detect: {res.get('av_detect')}\n"
            f"vx_family: {res.get('vx_family')}\n"
            f"type_short: {', '.join(res.get('type_short', []))}\n"
            f"threat_score: {res.get('threat_score')}\n"
            f"threat_level: {res.get('threat_level')}\n"
            f"verdict: {res.get('verdict')}\n"
        )
    return "\n".join(formatted)

def vulncheck_cve(cve_to_query):
    url = f"https://api.vulncheck.com/v3/index/vulncheck-kev?cve={cve_to_query}"
    headers = {"Accept": "application/json", "Authorization": APIs_Keys['vulncheck_key']}
    result = safe_api_call("Vulncheck", "GET", url, headers=headers, timeout=15)
    if "error" in result:
        return result["error"]
    data_list = result.get("data")
    if data_list:
        data = data_list[0]
        output = [
            {'CVE': data['cve'][0]},
            {'Date Added': data['date_added']},
            {'Vendor Project': data['vendorProject']},
            {'Product': data['product']},
            {'Short Description': data['shortDescription']},
            {'Required Action': data['required_action']},
            {'URL': data['vulncheck_reported_exploitation'][0]['url'] if data['vulncheck_reported_exploitation'] else 'URL not available'}
        ]
        return "=== Vulncheck ===\n" + "\n".join(f"{k}: {v}" for item in output for k, v in item.items())
    else:
        return f"=== Vulncheck ===\nNo data found for CVE: {cve_to_query}"

def tenable_cve(cve_to_query):
    url = f'https://www.tenable.com/cve/{cve_to_query}'
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        script_tag = soup.find('script', {'id': '__NEXT_DATA__'})
        if script_tag:
            json_data = json.loads(script_tag.string)
            cve_info = json_data['props']['pageProps']['cve']
            cpe = ', '.join(cve_info.get('cpe', [])) if cve_info.get('cpe') else 'N/A'
            references = "\n".join(f"Publication Date: {ref['publication_date']}\nTags: {', '.join(ref['tags'])}\nURL: {ref['url']}" for ref in cve_info.get('references', []))
            return (
                f"\n=== Tenable ===\n"
                f"CVE ID: {cve_info.get('doc_id', 'N/A')}\n"
                f"Description: {cve_info.get('description', 'N/A')}\n"
                f"Publication Date: {cve_info.get('publication_date', 'N/A')}\n"
                f"Deprecated: {cve_info.get('deprecated', 'N/A')}\n"
                f"CVSS 2.0 Base Score: {cve_info.get('cvss2_base_score', 'N/A')}\n"
                f"CVSS 2.0 Severity: {cve_info.get('cvss2_severity', 'N/A')}\n"
                f"CVSS 2.0 Base Vector: {cve_info.get('cvss2_base_vector', 'N/A')}\n"
                f"CVSS 3.0 Base Score: {cve_info.get('cvss3_base_score', 'N/A')}\n"
                f"CVSS 3.0 Severity: {cve_info.get('cvss3_severity', 'N/A')}\n"
                f"CVSS 3.0 Base Vector: {cve_info.get('cvss3_base_vector', 'N/A')}\n"
                f"CPE: {cpe}\n"
                f"References:\n{references}"
            )
        else:
            return "=== Tenable ===\nFailed to find the JSON data script tag."
    except requests.exceptions.RequestException as e:
        return f"=== Tenable ===\nFailed to retrieve the webpage: {e}"

def whois_info(query):
    try:
        socket.inet_aton(query)
    except socket.error:
        pass
    try:
        result = whois.whois(query)
        return "=== Whois ===\n" + "\n".join(f"{k}: {v}" for k, v in result.items())
    except Exception as e:
        return f"=== Whois ===\nError: An error occurred while fetching Whois information: {e}"
