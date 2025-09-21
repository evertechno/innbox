# streamlit_gmail_superhuman.py
# Streamlit app: Google OAuth + Gmail management + Gemini AI draft generation
# Requirements:
#   pip install streamlit google-auth google-auth-oauthlib google-api-python-client google-genai
# Setup steps (brief):
# 1. Enable Gmail API on Google Cloud Console and create OAuth client credentials.
# 2. Add your Streamlit redirect URI (e.g. http://localhost:8501/) in the OAuth client "Authorized redirect URIs".
# 3. Put the Google OAuth client info in Streamlit secrets (see below example).
# 4. Add your Gemini API key to the environment as GEMINI_API_KEY.
# 5. Run: streamlit run streamlit_gmail_superhuman.py

# Example .streamlit/secrets.toml
# [google]
# client_id = "<YOUR_CLIENT_ID>.apps.googleusercontent.com"
# client_secret = "<YOUR_CLIENT_SECRET>"
# redirect_uri = "http://localhost:8501/"

import streamlit as st
import os
import json
import base64
import time
from urllib.parse import urlencode
from email.mime.text import MIMEText

# Google auth & API
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Gemini AI
from google import genai
from google.genai import types

# ---------------------------
# Helper / Config
# ---------------------------
SCOPES = [
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/gmail.compose',
    'openid', 'email', 'profile'
]

st.set_page_config(page_title="Superhuman-like Gmail — Streamlit", layout='wide')

if 'creds' not in st.session_state:
    st.session_state.creds = None

# load google client config from secrets
if 'google' not in st.secrets:
    st.sidebar.error("Google OAuth client not found in Streamlit secrets. Add [google] keys in .streamlit/secrets.toml")
    st.stop()

google_conf = st.secrets['google']
CLIENT_CONFIG = {
    "web": {
        "client_id": google_conf.get('client_id'),
        "project_id": google_conf.get('project_id', ''),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_secret": google_conf.get('client_secret'),
        "redirect_uris": [google_conf.get('redirect_uri', 'http://localhost:8501/')]
    }
}

# ---------------------------
# OAuth Flow helpers
# ---------------------------

def make_flow(state=None):
    flow = Flow.from_client_config(
        client_config=CLIENT_CONFIG,
        scopes=SCOPES,
        redirect_uri=CLIENT_CONFIG['web']['redirect_uris'][0]
    )
    if state:
        flow.params['state'] = state
    return flow


def start_auth():
    flow = make_flow()
    auth_url, _ = flow.authorization_url(prompt='consent', access_type='offline', include_granted_scopes='true')
    return auth_url


def exchange_code_and_store(code):
    flow = make_flow()
    flow.fetch_token(code=code)
    creds = flow.credentials
    # store serialized creds in session_state
    st.session_state.creds = creds_to_dict(creds)


def creds_to_dict(creds: Credentials):
    return {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }


def dict_to_creds(d):
    return Credentials(
        token=d.get('token'),
        refresh_token=d.get('refresh_token'),
        token_uri=d.get('token_uri'),
        client_id=d.get('client_id'),
        client_secret=d.get('client_secret'),
        scopes=d.get('scopes')
    )

# ---------------------------
# Gmail helpers
# ---------------------------

def build_gmail_service():
    if not st.session_state.creds:
        return None
    creds = dict_to_creds(st.session_state.creds)
    try:
        service = build('gmail', 'v1', credentials=creds, cache_discovery=False)
        return service
    except Exception as e:
        st.error(f"Failed to build Gmail service: {e}")
        return None


def list_inbox_messages(service, max_results=10):
    try:
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=max_results).execute()
        messages = results.get('messages', [])
        out = []
        for m in messages:
            msg = service.users().messages().get(userId='me', id=m['id'], format='metadata', metadataHeaders=['From','Subject','Date']).execute()
            headers = {h['name']:h['value'] for h in msg.get('payload', {}).get('headers', [])}
            out.append({'id': m['id'], 'snippet': msg.get('snippet'), 'headers': headers})
        return out
    except HttpError as e:
        st.error(f"Gmail API error: {e}")
        return []


def get_message_body(service, msg_id):
    try:
        msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
        parts = msg.get('payload', {}).get('parts', [])
        if not parts:
            return msg.get('snippet')
        for p in parts:
            if p.get('mimeType') == 'text/plain':
                data = p.get('body', {}).get('data')
                if data:
                    return base64.urlsafe_b64decode(data.encode('UTF-8')).decode('utf-8')
        return msg.get('snippet')
    except Exception as e:
        st.error(f"Failed to get message body: {e}")
        return ''


def create_raw_message(to, subject, body_text):
    message = MIMEText(body_text)
    message['to'] = to
    message['subject'] = subject
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return raw


def create_draft(service, to, subject, body_text):
    raw = create_raw_message(to, subject, body_text)
    try:
        draft = service.users().drafts().create(userId='me', body={'message':{'raw': raw}}).execute()
        return draft
    except Exception as e:
        st.error(f"Failed to create draft: {e}")
        return None


def send_message(service, to, subject, body_text):
    raw = create_raw_message(to, subject, body_text)
    try:
        sent = service.users().messages().send(userId='me', body={'raw': raw}).execute()
        return sent
    except Exception as e:
        st.error(f"Failed to send message: {e}")
        return None

# ---------------------------
# Gemini AI: Generate draft
# ---------------------------

def generate_draft_with_ai(prompt_text):
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return "[Gemini not configured] Please set GEMINI_API_KEY in environment."

    client = genai.Client(api_key=api_key)
    model = "gemini-2.5-flash-lite"

    contents = [
        types.Content(
            role="user",
            parts=[types.Part.from_text(text=prompt_text)],
        ),
    ]
    generate_content_config = types.GenerateContentConfig(
        thinking_config=types.ThinkingConfig(thinking_budget=0),
        safety_settings=[
            types.SafetySetting(category="HARM_CATEGORY_HARASSMENT", threshold="BLOCK_LOW_AND_ABOVE"),
            types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH", threshold="BLOCK_LOW_AND_ABOVE"),
            types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold="BLOCK_LOW_AND_ABOVE"),
            types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_LOW_AND_ABOVE"),
        ],
    )

    output = []
    for chunk in client.models.generate_content_stream(
        model=model,
        contents=contents,
        config=generate_content_config,
    ):
        if chunk.text:
            output.append(chunk.text)
    return "".join(output).strip()

# ---------------------------
# UI
# ---------------------------

st.title("Superhuman-like Gmail in Streamlit (Gemini AI)")

# handle OAuth redirect callback
query_params = st.experimental_get_query_params()
if 'code' in query_params and not st.session_state.creds:
    code = query_params['code'][0]
    try:
        exchange_code_and_store(code)
        st.experimental_set_query_params()
        st.success("Successfully signed in!")
        st.experimental_rerun()
    except Exception as e:
        st.error(f"Failed to exchange code: {e}")

# Sidebar controls
with st.sidebar:
    st.header("Account")
    if not st.session_state.creds:
        if st.button("Sign in with Google"):
            auth_url = start_auth()
            st.write("Click the link to authenticate:")
            st.markdown(f"[Authenticate here]({auth_url})")
            st.stop()
        st.info("To use this app you must authenticate with Google. Click 'Sign in with Google'.")
    else:
        creds = dict_to_creds(st.session_state.creds)
        st.write("Authenticated")
        if st.button("Sign out"):
            st.session_state.creds = None
            st.experimental_rerun()

    st.markdown("---")
    st.header('AI')
    st.write("Using Gemini AI (via google-genai)")

# Main area
if not st.session_state.creds:
    st.info("Please sign in via the sidebar to continue.")
    st.stop()

service = build_gmail_service()
if service is None:
    st.error("Unable to build Gmail service. Try signing in again.")
    st.stop()

cols = st.columns([2,3])

with cols[0]:
    st.subheader("Inbox — latest")
    msgs = list_inbox_messages(service, max_results=15)
    for m in msgs:
        hdr = m.get('headers', {})
        subj = hdr.get('Subject', '(no subject)')
        frm = hdr.get('From', '')
        date = hdr.get('Date', '')
        with st.expander(f"{subj} — {frm}"):
            st.write(m.get('snippet'))
            if st.button("Open full", key=f"open_{m['id']}"):
                body = get_message_body(service, m['id'])
                st.code(body)

with cols[1]:
    st.subheader("Generate / Compose")
    selected_msg_id = st.selectbox("Generate draft from message (optional)", options=[None] + [m['id'] for m in msgs])
    original_text = ""
    if selected_msg_id:
        original_text = get_message_body(service, selected_msg_id)
        st.markdown("**Original message (source):**")
        st.code(original_text[:1000])

    user_instructions = st.text_area("Tell Gemini what you want the reply to do (tone, length, points to cover)")
    if not user_instructions and original_text:
        user_instructions = f"Write a concise professional reply to the following message. Keep it <= 6 sentences. Include key points and next steps.\n\nMessage:\n{original_text[:2000]}"

    if st.button("Generate draft"):
        prompt_text = user_instructions
        if original_text:
            prompt_text = f"Original message:\n{original_text}\n\nInstructions:\n{user_instructions}"
        with st.spinner("Generating draft with Gemini..."):
            draft_text = generate_draft_with_ai(prompt_text)
        st.session_state['last_generated'] = draft_text
        st.success("Draft generated — edit or save below")

    draft = st.text_area("Draft (editable)", value=st.session_state.get('last_generated', ''), height=250)

    to_addr = st.text_input("To (email)")
    subject = st.text_input("Subject", value=("Re: " + (msgs[0]['headers'].get('Subject','') if msgs else '')))

    c1, c2, c3 = st.columns(3)
    with c1:
        if st.button("Save as Draft"):
            if not to_addr:
                st.error("Please provide a recipient in 'To'")
            else:
                res = create_draft(service, to_addr, subject, draft)
                if res:
                    st.success("Saved draft in Gmail")
    with c2:
        if st.button("Send"):
            if not to_addr:
                st.error("Please provide a recipient in 'To'")
            else:
                res = send_message(service, to_addr, subject, draft)
                if res:
                    st.success("Message sent")
    with c3:
        if st.button("Save locally (.eml)"):
            raw = create_raw_message(to_addr, subject, draft)
            b = base64.urlsafe_b64decode(raw.encode())
            filename = f"draft_{int(time.time())}.eml"
            with open(filename, 'wb') as f:
                f.write(b)
            st.markdown(f"Saved to server as `{filename}`. Download from server or implement server-side send.")

st.markdown('---')
st.caption('This is a starter app — improve error handling, token refresh logic, and UI/UX for production.')
