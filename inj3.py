import re
import sys
import requests
import jsbeautifier
from urllib.parse import urlparse, parse_qs

def get_js_content(file_path_or_url):
    """Fetch JavaScript content from a local file or a remote URL."""
    try:
        if file_path_or_url.startswith("http://") or file_path_or_url.startswith("https://"):
            response = requests.get(file_path_or_url, timeout=10)
            response.raise_for_status()
            return response.text
        else:
            with open(file_path_or_url, "r", encoding="utf-8") as file:
                return file.read()
    except Exception as e:
        print(f"[ERROR] Could not read JavaScript file: {e}")
        sys.exit(1)

def pretty_print_js(js_content):
    """De-minify JavaScript using jsbeautifier."""
    return jsbeautifier.beautify(js_content)

def find_eval_vulnerabilities(js_content):
    """Find and analyze occurrences of eval() in the JavaScript file."""
    eval_patterns = [
        r"eval\s*\((.*?)\)",  # Basic eval() detection
        r"setTimeout\s*\((.*?)\)",  # Detects setTimeout with dynamic code
        r"setInterval\s*\((.*?)\)",  # Detects setInterval with dynamic code
        r"Function\s*\((.*?)\)"  # Detects new Function() calls
    ]
    
    dangerous_sources = [
        "document.URL", "document.location", "window.location",
        "document.cookie", "localStorage.getItem", "sessionStorage.getItem",
        "innerHTML", "outerHTML", "document.write", "fetch(", "XMLHttpRequest"
    ]

    vulnerabilities = []
    js_lines = js_content.split("\n")
    
    for pattern in eval_patterns:
        matches = re.finditer(pattern, js_content, re.MULTILINE | re.IGNORECASE)
        
        for match in matches:
            eval_code = match.group(1).strip()
            line_number = js_content[:match.start()].count("\n") + 1
            
            # Identify if the eval() input contains dangerous sources
            unsafe = any(source in eval_code for source in dangerous_sources)
            
            # Extract context: few lines before and after the eval() call
            start_line = max(0, line_number - 3)
            end_line = min(len(js_lines), line_number + 3)
            context = "\n".join(js_lines[start_line:end_line])

            vulnerabilities.append({
                "type": "eval",
                "code": eval_code,
                "line": line_number,
                "context": context,
                "potential_risk": unsafe
            })
    
    return vulnerabilities

def identify_injection_risks(vulnerabilities):
    """Analyze eval() calls for injection risks."""
    for vuln in vulnerabilities:
        code_snippet = vuln["code"]
        risk_factors = []
        
        if "document.URL" in code_snippet or "window.location" in code_snippet:
            risk_factors.append("[HIGH] User-controlled URL can be injected.")
        
        if "document.cookie" in code_snippet:
            risk_factors.append("[HIGH] Cookies can be injected.")

        if "innerHTML" in code_snippet or "document.write" in code_snippet:
            risk_factors.append("[HIGH] DOM manipulation detected.")

        if "fetch(" in code_snippet or "XMLHttpRequest" in code_snippet:
            risk_factors.append("[MEDIUM] Data fetched from external sources.")

        if "(" in code_snippet and ")" in code_snippet:
            risk_factors.append("[INFO] Dynamic function execution detected.")

        vuln["injection_risks"] = risk_factors

def report_findings(vulnerabilities):
    """Prints a detailed report of potential security issues found in the JavaScript file."""
    if not vulnerabilities:
        print("[INFO] No direct eval() vulnerabilities detected.")
    else:
        print("\n[WARNING] Potential eval() vulnerabilities found:\n")
        for vuln in vulnerabilities:
            print(f" - Found on Line {vuln['line']}")
            print(f"   Code: {vuln['code']}")
            print(f"   Context:\n{vuln['context']}")
            if vuln["potential_risk"]:
                print("   [!!!] HIGH RISK: Uses a potentially unsafe input source!")
            else:
                print("   [!] Moderate Risk: eval() usage found but no obvious injection vector.")

            if vuln.get("injection_risks"):
                print("   [**] Injection Risk Analysis:")
                for risk in vuln["injection_risks"]:
                    print(f"      - {risk}")

            print("-" * 80)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <js_file_or_url>")
        sys.exit(1)

    js_file_or_url = sys.argv[1]
    js_content = get_js_content(js_file_or_url)

    # Pretty print / de-minify JS if necessary
    js_content = pretty_print_js(js_content)

    vulnerabilities = find_eval_vulnerabilities(js_content)
    identify_injection_risks(vulnerabilities)
    report_findings(vulnerabilities)
  
