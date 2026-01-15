import streamlit as st
import requests
from requests_oauthlib import OAuth2Session
import json

# App title
st.title("💬 ReddyBot")
st.write("Welcome to ReddyBot. Ask me anything about Xcel's Design and Construction Standards.")

# OAuth configuration
AUTH_URL = "https://<your-databricks-workspace>/oidc/oauth2/v1/authorize"
TOKEN_URL = "https://<your-databricks-workspace>/oidc/oauth2/v1/token"
CLIENT_ID = "<your-client-id>"
CLIENT_SECRET = "<your-client-secret>"
REDIRECT_URI = "http://localhost:8501"  # or your deployed Streamlit URL
SCOPE = ["openid"]

# Initialize OAuth session
if "token" not in st.session_state:
    oauth = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI, scope=SCOPE)
    authorization_url, state = oauth.authorization_url(AUTH_URL)
    st.write(f"[Login with Databricks]({authorization_url})")
else:
    st.success("Authenticated with Databricks!")

# After redirect, exchange code for token
if "code" in st.query_params:
    oauth = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI, scope=SCOPE)
    token = oauth.fetch_token(TOKEN_URL, client_secret=CLIENT_SECRET, code=st.query_params["code"])
    st.session_state["token"] = token
    st.experimental_rerun()

# Databricks endpoint
DATABRICKS_API_URL = "https://dbc-beada314-1494.cloud.databricks.com/serving-endpoints/agents_sandbox_shared-distribution-reddy_bot/invocations"

# Initialize chat history
if "messages" not in st.session_state:
    st.session_state.messages = []

# Display previous messages
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Chat input
if prompt := st.chat_input("How can I help?"):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # Prepare payload
    payload = {
        "dataframe_records": [
            {"messages": st.session_state.messages}
        ]
    }

    headers = {
        "Authorization": f"Bearer {st.session_state['token']['access_token']}",
        "Content-Type": "application/json"
    }

    # Stream response
    

with st.chat_message("assistant"):
    placeholder = st.empty()
    bot_reply = ""
    buffer = ""

    try:
        with requests.post(DATABRICKS_API_URL, json=payload, headers=headers, stream=True) as r:
            r.raise_for_status()

            for chunk in r.iter_content(chunk_size=1024):
                if not chunk:
                    continue

                buffer += chunk.decode("utf-8")

                # Parse any valid JSON objects from the buffer
                while True:
                    buffer = buffer.lstrip()

                    if not buffer.startswith("{"):
                        break

                    try:
                        obj, idx = json.JSONDecoder().raw_decode(buffer)
                        buffer = buffer[idx:]
                    except Exception:
                        break  # Wait for more data

                    # Extract assistant text
                    if "content" in obj:
                        for c in obj["content"]:
                            if "text" in c:
                                bot_reply += c["text"]
                                placeholder.markdown(bot_reply)

    except Exception as e:
        bot_reply = f"Error: {e}"
        placeholder.markdown(bot_reply)

# Save clean output
st.session_state.messages.append({
    "role": "assistant",
    "content": bot_reply
})
