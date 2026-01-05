"""
XML XXE CTF Challenge (Medium)
Vulnerability: XML External Entity Injection for file disclosure
"""
from flask import Flask, request, render_template_string, jsonify
from lxml import etree
import os

app = Flask(__name__)
FLAG = os.getenv("FLAG", "CTF{xxe_file_disclosure}")

HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>XML User Import</title>
    <style>
        :root { color-scheme: light dark; }
        body { font-family: system-ui, sans-serif; max-width: 800px; margin: 2rem auto; padding: 0 1rem; }
        h1 { color: #2563eb; }
        textarea { width: 100%; height: 200px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; padding: 0.6rem 0.7rem; border: 1px solid #cbd5e1; border-radius: 8px; }
        textarea:focus-visible, button:focus-visible { outline: 3px solid #93c5fd; outline-offset: 2px; }
        button { padding: 0.6rem 1rem; background: #2563eb; color: white; border: 1px solid #1d4ed8; border-radius: 8px; cursor: pointer; margin-top: 0.5rem; font-weight:600; }
        button:hover { background: #1d4ed8; }
        .result { background: #ecfdf5; color: #065f46; padding: 1rem; border-radius: 8px; margin-top: 1rem; border: 1px solid #a7f3d0; }
        .result pre { margin: 0; white-space: pre-wrap; }
        .error { background: #fef2f2; color: #991b1b; padding: 1rem; border-radius: 8px; border: 1px solid #fecaca; }
        .example { background: #f3f4f6; padding: 1rem; border-radius: 8px; margin: 1rem 0; font-family: monospace; font-size: 0.9rem; }
        .hint { color: #6b7280; font-size: 0.9rem; margin-top: 1rem; }
        a.back { color:#2563eb; text-decoration:none; }
        a.back:hover { text-decoration:underline; }
        @media (prefers-color-scheme: dark) {
            body { background: #0f172a; color: #e2e8f0; }
            h1 { color: #60a5fa; }
            textarea { background: #1e293b; color: #e2e8f0; border-color: #334155; }
            .example { background: #1e293b; color: #e2e8f0; }
            .result { background: #064e3b; color: #a7f3d0; border-color: #065f46; }
            .error { background: #450a0a; color: #fecaca; border-color: #7f1d1d; }
        }
    </style>
</head>
<body>
    <p><a class="back" href="{{ portal_url }}">← Terug naar portaal</a></p>
    <h1>📄 XML User Import Service</h1>
    <p>Submit XML data to import user information into our system:</p>
    
    <div class="example">
        <strong>Example XML format:</strong><br>
        &lt;user&gt;<br>
        &nbsp;&nbsp;&lt;name&gt;John Doe&lt;/name&gt;<br>
        &nbsp;&nbsp;&lt;email&gt;john@example.com&lt;/email&gt;<br>
        &nbsp;&nbsp;&lt;role&gt;user&lt;/role&gt;<br>
        &lt;/user&gt;
    </div>
    
    <form method="POST">
        <textarea name="xml" placeholder="Paste your XML here...">{{ xml or '' }}</textarea>
        <br>
        <button type="submit">Import User</button>
    </form>
    
    {% if error %}
    <div class="error">{{ error }}</div>
    {% endif %}
    
    {% if result %}
    <div class="result">
        <strong>✅ User Imported Successfully:</strong>
        <pre>{{ result }}</pre>
    </div>
    {% endif %}
    
    <p class="hint">💡 Hint: XML parsers can be quite powerful... and dangerous. Ever heard of DTDs?</p>
    <p class="hint">📖 The flag is stored at <code>/flag.txt</code> on the server.</p>
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None
    xml_input = None
    scheme = request.headers.get("X-Forwarded-Proto", request.scheme or "http")
    forwarded_host = request.headers.get("X-Forwarded-Host")
    raw_host = (forwarded_host.split(",")[0].strip() if forwarded_host else request.host)
    portal_host = raw_host.split(":")[0]
    portal_url = f"{scheme}://{portal_host}/"
    
    if request.method == "POST":
        xml_input = request.form.get("xml", "")
        if xml_input:
            try:
                # VULNERABLE: Parser allows external entities
                # resolve_entities=True and no_network=False allow XXE
                parser = etree.XMLParser(
                    resolve_entities=True,
                    no_network=False,
                    dtd_validation=False,
                    load_dtd=True
                )
                root = etree.fromstring(xml_input.encode(), parser)
                
                # Extract user data
                name = root.find("name")
                email = root.find("email")
                role = root.find("role")
                
                user_data = {
                    "name": name.text if name is not None else "N/A",
                    "email": email.text if email is not None else "N/A",
                    "role": role.text if role is not None else "N/A"
                }
                
                result = f"Name: {user_data['name']}\nEmail: {user_data['email']}\nRole: {user_data['role']}"
                
            except etree.XMLSyntaxError as e:
                error = f"XML Syntax Error: {e}"
            except Exception as e:
                error = f"Error processing XML: {e}"
    
    return render_template_string(HTML_TEMPLATE, result=result, error=error, xml=xml_input, portal_url=portal_url)


@app.route("/api/import", methods=["POST"])
def api_import():
    """API endpoint for XML import (for curl/tool usage)"""
    if not request.data:
        return jsonify({"error": "No XML data provided"}), 400
    
    try:
        parser = etree.XMLParser(
            resolve_entities=True,
            no_network=False,
            dtd_validation=False,
            load_dtd=True
        )
        root = etree.fromstring(request.data, parser)
        
        name = root.find("name")
        email = root.find("email")
        role = root.find("role")
        
        return jsonify({
            "status": "imported",
            "user": {
                "name": name.text if name is not None else None,
                "email": email.text if email is not None else None,
                "role": role.text if role is not None else None
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/healthz")
def healthz():
    return {"status": "ok"}


if __name__ == "__main__":
    # Write flag to /flag.txt
    with open("/flag.txt", "w") as f:
        f.write(FLAG)
    app.run(host="0.0.0.0", port=5000, debug=False)
