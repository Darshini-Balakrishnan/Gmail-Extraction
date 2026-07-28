"""
Gmail -> Structured Excel, on-demand, per-user login
---------------------------------------------------------------
User enters their email, clicks "Connect Google Account", authorizes
via Google's OAuth screen, and the app reads their Gmail directly
(body + attachments) - no scheduling, no Google Drive step needed.
Claude extracts structured product/quote data, and the result is
served back as a downloadable Excel file in the UI.

SETUP (one-time)
  1. Google Cloud Console -> new project
  2. Enable the "Gmail API"
  3. OAuth consent screen -> External -> fill basic info -> add your
     Gmail scope (gmail.readonly) -> add yourself as a test user
     (while the app is unverified, only test users can log in)
  4. Credentials -> Create Credentials -> OAuth client ID ->
     Application type: Web application
     Authorized redirect URI: the exact URL this app runs at,
     e.g. http://localhost:8501 for local testing
  5. Download the JSON -> save as client_secret.json next to this file
  6. Get an Anthropic API key: https://console.anthropic.com
  7. pip install -r requirements.txt
  8. Set env vars:
        ANTHROPIC_API_KEY=sk-ant-...
        OAUTH_REDIRECT_URI=http://localhost:8501
  9. Run: streamlit run app.py

NOTE: while your OAuth app is "unverified" in Google Cloud, only the
test users you explicitly add can log in. To let *any* user log in,
you'd need to submit the app for Google's verification review.
"""

import os
import io
import re
import json
import base64
import secrets
import hashlib
from datetime import datetime

import streamlit as st
import pandas as pd
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import anthropic

def _safe_secret(key, default=None):
    """st.secrets throws if no secrets.toml exists at all (e.g. local dev
    without one) - this falls back cleanly instead of crashing."""
    try:
        return st.secrets.get(key, default)
    except Exception:
        return default


def _safe_secret_section(key):
    try:
        return st.secrets[key] if key in st.secrets else None
    except Exception:
        return None


# ============ CONFIG ============
# Reads secrets from Streamlit's secrets manager (st.secrets) when deployed,
# falling back to a local client_secret.json + env vars for local dev.
REDIRECT_URI = _safe_secret("OAUTH_REDIRECT_URI", os.environ.get("OAUTH_REDIRECT_URI", "http://localhost:8501"))
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly",
          "https://www.googleapis.com/auth/userinfo.email",
          "openid"]
ANTHROPIC_MODEL = "claude-sonnet-5"  # check docs.claude.com for the latest model string
DEFAULT_QUERY = "newer_than:30d"


def get_client_config():
    """Build the OAuth client config from st.secrets if present (deployed),
    otherwise fall back to a local client_secret.json file (local dev)."""
    g = _safe_secret_section("google_oauth")
    if g:
        return {
            "web": {
                "client_id": g["client_id"],
                "client_secret": g["client_secret"],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [REDIRECT_URI],
            }
        }
    return None
# =================================

EXTRACTION_PROMPT = """You are extracting product/quotation data from ONE email
thread. You are given the visible Gmail sender, plus the full combined content
of the email: body text (which may contain nested "Forwarded message" /
"-----Original Message-----" blocks with earlier From/Sent/To headers quoted
inside it), and the text of every attachment (PDF/Excel/CSV), plus any
attached images shown to you directly.

STEP 1 - Find the ROOT sender (this is the most important part):
Do NOT just use the visible Gmail "From" below - that is often just the
person who forwarded the email onward. Instead, search the body text for
quoted headers like "From:", "Sent:", "---------- Forwarded message ---------",
"-----Original Message-----" etc. Follow the chain to the EARLIEST/DEEPEST
original sender - that is the actual company/supplier who first sent this
information. If attachments (letterhead, PDF, signature) show a company name,
use that to confirm/fill in the root sender's company name.

Visible Gmail sender (do not treat as the root sender unless no forwarding
is present): {visible_from}
Subject: {subject}

STEP 2 - Decide relevance:
If this email is NOT about a product, quotation, price list, or technical
specification (e.g. it's a personal message, newsletter, referral, meeting
note, etc. with an unrelated attachment like a resume), return an empty
JSON array: []

STEP 3 - Extract line items:
For each distinct product/item found (across the body AND every attachment),
output one object with ALL of these keys (use null if truly not present):
- supplier_company   (the ROOT company name from Step 1)
- supplier_contact    (root contact person's name)
- supplier_email      (root sender's actual email address)
- supplier_phone
- item_description
- part_or_catalog_no
- specification        (size/rating/model, whatever describes the part)
- quantity             (NUMBER ONLY, e.g. 6 - never include units like "NOS"/"PCS" here)
- unit                 (the unit of measure if stated, e.g. "NOS", "PCS", "Mtr", "Kg" - else null)
- unit_price           (NUMBER ONLY, no currency symbol or text)
- total_price          (NUMBER ONLY, no currency symbol or text)
- currency
- discount_or_terms    (discount %, GST, delivery, payment terms - combine into one short string)
- source_note          (e.g. "from PDF attachment X" or "from email body")

quantity, unit_price, and total_price must always be a plain number (or null) -
never a string, never combined with text. Put any unit/text alongside a number
into the "unit" or "discount_or_terms" field instead.

IMPORTANT - price columns can be labeled many different ways: "Rate", "Unit
Cost", "Amount", "USD", "Price/Unit", "Value", a bare "$" or currency symbol
column, or a column header only implying currency without saying "price" at
all. Check every column in every table/sheet for numeric values that could be
a per-unit or total price before concluding a price isn't present - do not
skip a price just because the column isn't literally named "price".

IMPORTANT - if an attachment has multiple sheets, pages, or the item list
continues beyond what looks like a natural stopping point, keep extracting
ALL items through to the actual end of the content provided. Do not stop
early or summarize/truncate the list yourself.

Repeat supplier_company/contact/email/phone identically on EVERY row - do not
put supplier info in a separate row by itself.

Return ONLY a valid JSON array of these objects. No text outside the array.

COMBINED CONTENT (body + all attachment text):
---
{doc_text}
---
"""


def _generate_pkce_pair():
    """Manually generate a PKCE verifier/challenge pair. We manage this
    ourselves (rather than relying on the library's autogenerate_code_verifier)
    because the verifier needs to survive a full browser redirect out to
    Google and back - st.session_state isn't reliable for that, since a full
    page navigation away can reset it. Instead we smuggle the verifier
    through Google's 'state' parameter, which is guaranteed to round-trip
    back to us unchanged."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode("ascii")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    return verifier, challenge


def get_flow():
    client_config = get_client_config()
    if client_config:
        return Flow.from_client_config(client_config, scopes=SCOPES, redirect_uri=REDIRECT_URI)
    if os.path.exists("client_secret.json"):
        return Flow.from_client_secrets_file(
            "client_secret.json", scopes=SCOPES, redirect_uri=REDIRECT_URI
        )
    st.error(
        "No Google OAuth credentials found. If this app is deployed, add a "
        "[google_oauth] section with client_id and client_secret in your "
        "Streamlit app's Settings -> Secrets. If running locally, either add "
        "the same to .streamlit/secrets.toml, or place a client_secret.json "
        "file next to app.py."
    )
    st.stop()


def get_anthropic_client():
    api_key = _safe_secret("ANTHROPIC_API_KEY", os.environ.get("ANTHROPIC_API_KEY"))
    if not api_key:
        st.error("Set ANTHROPIC_API_KEY in Streamlit secrets (or as an env var locally).")
        st.stop()
    return anthropic.Anthropic(api_key=api_key)


# ---------- Gmail helpers ----------
def gmail_service(creds):
    return build("gmail", "v1", credentials=creds)


def list_messages(service, query):
    msgs, page_token = [], None
    while True:
        resp = service.users().messages().list(
            userId="me", q=query, pageToken=page_token, maxResults=100
        ).execute()
        msgs.extend(resp.get("messages", []))
        page_token = resp.get("nextPageToken")
        if not page_token or len(msgs) >= 200:
            break
    return msgs


def get_message(service, msg_id):
    return service.users().messages().get(userId="me", id=msg_id, format="full").execute()


def extract_body_text(payload):
    """Walk the MIME tree and pull out plain-text body content."""
    if payload.get("mimeType") == "text/plain" and "data" in payload.get("body", {}):
        return base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8", errors="ignore")
    for part in payload.get("parts", []):
        text = extract_body_text(part)
        if text:
            return text
    return ""


def extract_attachments(service, msg_id, payload, collected=None):
    """Walk the MIME tree, download every attachment's real bytes -
    including inline images that don't have a filename set (common for
    images embedded directly in the email body, not just formal attachments)."""
    if collected is None:
        collected = []
    for part in payload.get("parts", []):
        filename = part.get("filename")
        mime_type = part.get("mimeType", "")
        body = part.get("body", {})
        is_inline_image = (not filename) and mime_type.startswith("image/") and body.get("attachmentId")
        if (filename and body.get("attachmentId")) or is_inline_image:
            att = service.users().messages().attachments().get(
                userId="me", messageId=msg_id, id=body["attachmentId"]
            ).execute()
            content = base64.urlsafe_b64decode(att["data"])
            if not filename:
                ext = mime_type.split("/")[-1].replace("jpeg", "jpg")
                filename = f"inline_image_{len(collected)}.{ext}"
            collected.append((filename, content))
        if "parts" in part:
            extract_attachments(service, msg_id, part, collected)
    return collected


def file_to_text(filename, content):
    ext = filename.lower().split(".")[-1]
    try:
        if ext == "pdf":
            import pdfplumber
            with pdfplumber.open(io.BytesIO(content)) as pdf:
                return "\n".join(p.extract_text() or "" for p in pdf.pages)
        if ext in ("xlsx", "xls"):
            dfs = pd.read_excel(io.BytesIO(content), sheet_name=None)
            return "\n\n".join(f"Sheet: {n}\n{df.to_csv(index=False)}" for n, df in dfs.items())
        if ext == "csv":
            return content.decode("utf-8", errors="ignore")
    except Exception as e:
        return f"[Could not parse {filename}: {e}]"
    return None  # images handled via vision separately


INPUT_CHAR_LIMIT = 180000  # generous headroom under the model's context window


def claude_extract_combined(client, visible_from, subject, combined_text, images):
    """One call per email: body text + all attachment text combined, plus any
    image attachments passed as real image blocks. This avoids the earlier bug
    of each attachment producing its own separate/partial supplier info."""
    content = []
    for fname, media_type, b64 in images:
        content.append({"type": "image", "source": {"type": "base64", "media_type": media_type, "data": b64}})

    text_was_truncated = len(combined_text) > INPUT_CHAR_LIMIT
    doc_text = combined_text[:INPUT_CHAR_LIMIT] if combined_text.strip() else "[no text content - see attached image(s)]"
    prompt_text = EXTRACTION_PROMPT.format(visible_from=visible_from, subject=subject, doc_text=doc_text)
    content.append({"type": "text", "text": prompt_text})

    try:
        msg = client.messages.create(
            model=ANTHROPIC_MODEL, max_tokens=8192,
            messages=[{"role": "user", "content": content}],
        )
    except anthropic.APIStatusError as e:
        st.error(
            f"Anthropic API error ({e.status_code}): {e.message}\n\n"
            "Common causes: the model name isn't available to your account/plan, "
            "you're out of credits, or you've hit a rate limit. Check "
            "console.anthropic.com -> Plans & Billing and -> the model list "
            "under API docs to confirm ANTHROPIC_MODEL in app.py is valid for "
            "your account."
        )
        st.stop()

    raw = _get_text(msg)
    output_truncated = (msg.stop_reason == "max_tokens")
    rows = _parse_json(raw, truncated=output_truncated)

    if text_was_truncated:
        rows.append({
            "item_description": "INPUT_TRUNCATED",
            "notes": f"This email's combined body+attachment content was longer than "
                     f"{INPUT_CHAR_LIMIT:,} characters and got cut off before reaching "
                     f"Claude - items near the end of a long attachment/list may be "
                     f"missing. Consider processing this attachment separately.",
        })
    return rows


def _get_text(msg):
    """Claude's response can include non-text blocks (e.g. thinking) before
    the text block - find the text block by type rather than assuming index 0."""
    for block in msg.content:
        if block.type == "text":
            return block.text
    return ""


def _parse_json(raw, truncated=False):
    raw = raw.strip().replace("```json", "").replace("```", "").strip()

    # Some responses add a stray sentence before/after the array despite
    # instructions - grab from the first '[' to the last ']' to strip that.
    start = raw.find("[")
    end = raw.rfind("]")
    candidate = raw[start:end + 1] if (start != -1 and end != -1 and end > start) else raw

    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass

    # Response was cut off mid-array (hit max_tokens) - salvage whatever
    # complete {...} objects exist before the cutoff instead of losing
    # the whole email's worth of data to one truncated trailing item.
    if start != -1:
        salvaged = []
        depth = 0
        obj_start = None
        for i, ch in enumerate(raw[start:], start=start):
            if ch == "{":
                if depth == 0:
                    obj_start = i
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0 and obj_start is not None:
                    try:
                        salvaged.append(json.loads(raw[obj_start:i + 1]))
                    except json.JSONDecodeError:
                        pass
                    obj_start = None
        if salvaged:
            if truncated:
                salvaged.append({"item_description": "TRUNCATED",
                                  "notes": "Response hit the token limit - some items after this "
                                           "point may be missing. Consider narrowing the search or "
                                           "splitting this email's content."})
            return salvaged

    return [{"item_description": "PARSE_ERROR", "notes": raw[:500]}]


def run_extraction(creds, query, progress_cb=None):
    service = gmail_service(creds)
    client = get_anthropic_client()
    messages = list_messages(service, query)

    all_rows = []
    for i, m in enumerate(messages):
        full = get_message(service, m["id"])
        payload = full["payload"]
        headers = {h["name"]: h["value"] for h in payload.get("headers", [])}
        visible_from = headers.get("From", "")
        subject = headers.get("Subject", "")

        body_text = extract_body_text(payload)
        text_parts = [f"--- EMAIL BODY ---\n{body_text}"] if body_text else []
        images = []

        for fname, content in extract_attachments(service, m["id"], payload):
            ext = fname.lower().split(".")[-1]
            if ext in ("png", "jpg", "jpeg", "gif", "webp"):
                # skip tiny images - almost always logos/signature icons, not data
                if len(content) < 8000:
                    continue
                media_type = f"image/{'jpeg' if ext == 'jpg' else ext}"
                b64 = base64.standard_b64encode(content).decode("utf-8")
                images.append((fname, media_type, b64))
            else:
                text = file_to_text(fname, content)
                if text and text.strip():
                    text_parts.append(f"--- ATTACHMENT: {fname} ---\n{text}")

        combined_text = "\n\n".join(text_parts)
        if not combined_text.strip() and not images:
            rows = []  # nothing to extract from
        else:
            rows = claude_extract_combined(client, visible_from, subject, combined_text, images)

        for r in rows:
            r["_email_subject"] = subject
            r["_visible_gmail_from"] = visible_from
            r["_email_date"] = headers.get("Date", "")
            r["_processed_at"] = datetime.now().isoformat()
        all_rows.extend(rows)

        if progress_cb:
            progress_cb((i + 1) / max(len(messages), 1))

    df = pd.DataFrame(all_rows)

    def _extract_number(val):
        """Safety net: even with prompt instructions, a stray non-numeric
        value (e.g. '6 NOS') occasionally slips into a numeric column, which
        breaks Streamlit's Arrow-based table renderer (needs one consistent
        type per column). Salvage the leading number rather than losing it."""
        if pd.isna(val) or isinstance(val, (int, float)):
            return val
        match = re.search(r"[-+]?\d[\d,]*\.?\d*", str(val))
        if match:
            try:
                return float(match.group().replace(",", ""))
            except ValueError:
                return None
        return None

    for col in ("quantity", "unit_price", "total_price"):
        if col in df.columns:
            df[col] = df[col].apply(_extract_number)

    # Put the most useful columns first if present
    preferred = ["supplier_company", "supplier_contact", "supplier_email", "supplier_phone",
                 "item_description", "part_or_catalog_no", "specification", "quantity", "unit",
                 "unit_price", "total_price", "currency", "discount_or_terms", "source_note",
                 "_email_subject", "_visible_gmail_from", "_email_date", "_processed_at"]
    cols = [c for c in preferred if c in df.columns] + [c for c in df.columns if c not in preferred]
    return df[cols] if not df.empty else df


def build_excel(df):
    """Two-sheet workbook: deduped Suppliers, and full Product Details -
    mirrors the manually-built target format instead of one flat dump."""
    from openpyxl.styles import Font, PatternFill, Alignment

    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        # Suppliers sheet: dedupe by company+email, keep first-seen contact/phone
        sup_cols = ["supplier_company", "supplier_contact", "supplier_email", "supplier_phone"]
        sup_cols = [c for c in sup_cols if c in df.columns]
        if sup_cols:
            suppliers = (df[sup_cols + [c for c in ["_email_subject", "_email_date"] if c in df.columns]]
                         .drop_duplicates(subset=[c for c in sup_cols if c in ("supplier_company", "supplier_email")])
                         .reset_index(drop=True))
            suppliers.to_excel(writer, sheet_name="Suppliers", index=False)

        df.to_excel(writer, sheet_name="Product Details", index=False)

        # light formatting pass
        header_font = Font(bold=True, color="FFFFFF")
        header_fill = PatternFill(start_color="1F4E78", end_color="1F4E78", fill_type="solid")
        for sheet in writer.sheets.values():
            for cell in sheet[1]:
                cell.font = header_font
                cell.fill = header_fill
                cell.alignment = Alignment(wrap_text=True, vertical="top")
            for col in sheet.columns:
                max_len = max((len(str(c.value)) for c in col if c.value is not None), default=10)
                sheet.column_dimensions[col[0].column_letter].width = min(max(max_len + 2, 12), 45)

    buf.seek(0)
    return buf.getvalue()


# ============ UI ============
st.set_page_config(page_title="Gmail Data Extractor", layout="wide")
st.title("📧 Gmail -> Structured Excel")
st.caption("Log in with Google, pull product/quote data from your emails and attachments, download the Excel.")

if "credentials" not in st.session_state:
    st.session_state.credentials = None

email_input = st.text_input("Your email address (for reference)", placeholder="you@company.com")

query_params = st.query_params
if "code" in query_params and st.session_state.credentials is None:
    flow = get_flow()
    flow.code_verifier = query_params.get("state")  # restored from Google's round-tripped state param
    try:
        flow.fetch_token(code=query_params["code"])
        st.session_state.credentials = flow.credentials
        st.query_params.clear()
        st.rerun()
    except Exception as e:
        st.query_params.clear()  # the code is now used/dead either way - drop it so a rerun doesn't retry it
        st.error(
            f"Google sign-in failed: {e}\n\n"
            "Common causes: an incomplete/incorrect client_secret in your app's "
            "secrets, or the authorization code expired (codes are one-time use "
            "and expire quickly). Click 'Connect Google Account' below to get a "
            "fresh code and try again."
        )

if st.session_state.credentials is None:
    flow = get_flow()
    verifier, challenge = _generate_pkce_pair()
    auth_url, _ = flow.authorization_url(
        access_type="offline", include_granted_scopes="true", prompt="consent",
        code_challenge=challenge, code_challenge_method="S256",
        state=verifier,  # smuggled through Google's redirect so it survives the round trip
    )
    st.link_button("🔐 Connect Google Account", auth_url, type="primary")
else:
    st.success("Google account connected.")
    st.markdown("**Time range**")
    range_choice = st.radio(
        "How far back to search",
        ["Last 7 days", "Last 30 days", "Last 90 days", "Last 6 months", "Last year", "Custom date range", "All time"],
        index=1,  # defaults to Last 30 days
        horizontal=True,
    )

    range_map = {
        "Last 7 days": "newer_than:7d",
        "Last 30 days": "newer_than:30d",
        "Last 90 days": "newer_than:90d",
        "Last 6 months": "newer_than:6m",
        "Last year": "newer_than:1y",
        "All time": "",
    }

    if range_choice == "Custom date range":
        col_a, col_b = st.columns(2)
        with col_a:
            start_date = st.date_input("From")
        with col_b:
            end_date = st.date_input("Until")
        time_clause = f"after:{start_date.strftime('%Y/%m/%d')} before:{end_date.strftime('%Y/%m/%d')}"
    else:
        time_clause = range_map[range_choice]

    extra_terms = st.text_input(
        "Extra search terms (optional)", value="",
        help="Standard Gmail search syntax, e.g. has:attachment, from:someone@company.com, "
             "subject:quotation. Leave blank to just use the time range above.",
    )

    search_query = " ".join(part for part in [extra_terms.strip(), time_clause] if part)
    st.caption(f"Gmail query that will run: `{search_query or '(all mail)'}`")

    if range_choice in ("Last year", "All time"):
        st.warning("Wide ranges like this can pull in a lot of mail — this app processes "
                   "up to 200 matching emails per run (each one is a Claude API call, so "
                   "very wide ranges also cost more and take longer). Narrow the range or "
                   "add extra search terms above to stay focused.")

    if st.button("▶️ Extract now", type="primary"):
        progress = st.progress(0.0, text="Starting...")
        df = run_extraction(st.session_state.credentials, search_query,
                             progress_cb=lambda p: progress.progress(p, text=f"Processing... {int(p*100)}%"))
        progress.empty()
        st.session_state.result_df = df

    if "result_df" in st.session_state and not st.session_state.result_df.empty:
        df = st.session_state.result_df
        st.dataframe(df, width="stretch")

        excel_bytes = build_excel(df)
        st.download_button(
            "⬇️ Download Excel",
            data=excel_bytes,
            file_name=f"gmail_extract_{datetime.now().strftime('%Y%m%d_%H%M')}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
    elif "result_df" in st.session_state:
        st.info("No matching data found for that search filter.")

    if st.button("Log out"):
        st.session_state.credentials = None
        st.session_state.pop("result_df", None)
        st.rerun()
