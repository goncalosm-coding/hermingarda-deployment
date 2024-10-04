import streamlit as st
import os
import re  # Import regex module for email validation
from query_data import query_rag
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import credentials, firestore
import requests  # For REST API calls
import openai
import json

# Load environment variables
load_dotenv()

# Get the Firebase credentials JSON string from the environment variable
firebase_credentials_json = os.getenv("FIREBASE_SDK_KEY")

# Parse the JSON string to a dictionary
firebase_credentials_dict = json.loads(firebase_credentials_json)

# Initialize Firebase Admin SDK using the dictionary credentials
cred = credentials.Certificate(firebase_credentials_dict)

# Check if the default app already exists
if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)

# Initialize Firestore
db = firestore.client()

# Firebase user data retrieval function
def get_user_from_firebase(username):
    doc_ref = db.collection("users").document(username)
    doc = doc_ref.get()
    if doc.exists:
        return doc.to_dict()
    else:
        return None

# Check OpenAI API Key function
def check_openai_api_key(api_key):
    client = openai.OpenAI(api_key=api_key)
    try:
        client.models.list()
        return True
    except openai.APIError as e:
        print(f"OpenAI API returned an API Error: {e}")
        return False
    except openai.APIConnectionError as e:
        print(f"Failed to connect to OpenAI API: {e}")
        return False
    except openai.RateLimitError as e:
        print(f"OpenAI API request exceeded rate limit: {e}")
        return False

# Firebase-specific functions
def save_user_to_firebase(username, api_key):
    user_data = {
        "api_key": api_key,
        "messages": [],
        "receive_forwarded_messages": True,
        "logged_in": False
    }
    db.collection("users").document(username).set(user_data)

def save_messages_to_firebase(username, messages):
    db.collection("users").document(username).update({"messages": messages})

def update_user_logged_in_state(username, logged_in):
    db.collection("users").document(username).update({"logged_in": logged_in})

# Validate email
def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None

# Forward messages function with recipient check
def forward_message(user_prompt, assistant_response, recipient, sender):
    recipient_data = get_user_from_firebase(recipient)
    if recipient_data and recipient_data.get("receive_forwarded_messages", True):  
        recipient_data["messages"].append({
            "role": "user",
            "content": f"🔄 [Forwarded from {sender}]: {user_prompt}" 
        })
        recipient_data["messages"].append({
            "role": "assistant",
            "content": f"🔄 [Forwarded from {sender}]: {assistant_response}"  
        })
        save_messages_to_firebase(recipient, recipient_data["messages"])
        return True
    else:
        return False 

# Streamlit UI
st.title(":violet[Hermingarda] - Your PNA Assistant")

# Check login status
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "username" not in st.session_state:
    st.session_state.username = ""

if "api_key" not in st.session_state:
    st.session_state.api_key = ""

# Authentication
if not st.session_state.logged_in:
    tab1, tab2 = st.tabs(["Login", "Register"])

    with tab1:
        st.subheader("Login")
        login_username = st.text_input("Email", key="login_username")
        login_password = st.text_input("Password", type="password", key="login_password")

        if st.button("Login"):
            if is_valid_email(login_username):
                try:
                    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={os.getenv('FIREBASE_API_KEY')}"
                    payload = {
                        "email": login_username,
                        "password": login_password,
                        "returnSecureToken": True
                    }
                    response = requests.post(url, json=payload)
                    data = response.json()

                    if response.status_code == 200:
                        st.success(f"Welcome back, {login_username}!")
                        st.session_state.logged_in = True
                        st.session_state.username = login_username
                        
                        # Load user data and set API key in session state
                        user_data = get_user_from_firebase(login_username)
                        st.session_state.messages = user_data.get("messages", [])
                        st.session_state.api_key = user_data.get("api_key", "")
                        st.write(f"API Key Loaded: {st.session_state.api_key}")  # Debugging line
                        update_user_logged_in_state(login_username, True)
                        st.rerun()
                    else:
                        st.error(data.get("error", {}).get("message", "Invalid email or password."))

                except Exception as e:
                    st.error(f"Error during login: {e}")
            else:
                st.error("Please enter a valid email address.")

    with tab2:
        st.subheader("Register")
        register_username = st.text_input("Email", key="register_username")
        register_password = st.text_input("Password", type="password", key="register_password")
        register_api_key = st.text_input("API Key", type="password", key="register_api_key")

        if st.button("Register"):
            if not is_valid_email(register_username):
                st.error("Please enter a valid email address.")
            else:
                if check_openai_api_key(register_api_key):
                    try:
                        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={os.getenv('FIREBASE_API_KEY')}"
                        payload = {
                            "email": register_username,
                            "password": register_password,
                            "returnSecureToken": True
                        }
                        response = requests.post(url, json=payload)
                        if response.status_code == 200:
                            save_user_to_firebase(register_username, register_api_key)
                            st.success("Registration successful! You can now log in.")
                        else:
                            st.error(response.json().get("error", {}).get("message", "Error during registration."))

                    except Exception as e:
                        st.error(f"Error during registration: {e}")
                else:
                    st.error("Invalid API Key. Please check and try again.")

# If logged in
if st.session_state.logged_in:
    username = st.session_state.username

    # Cache messages on load
    if "messages" not in st.session_state:
        user_data = get_user_from_firebase(username)
        st.session_state.messages = user_data["messages"]

    # Display messages
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    prompt = st.chat_input("Ask a question based on the medical research documents...")

    if prompt:
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        print(f"Using API Key: {st.session_state.api_key}")  # Debugging line
        response = query_rag(prompt, st.session_state.api_key)  # Use the cached API key from session state
        st.session_state.messages.append({"role": "assistant", "content": response})

        with st.chat_message("assistant"):
            st.markdown(response)

        save_messages_to_firebase(username, st.session_state.messages)

    # Sidebar options
    with st.sidebar:
        st.subheader("User Preferences")
        receive_forwarded = st.checkbox("Receive Messages",
                                        value=get_user_from_firebase(username).get("receive_forwarded_messages", True))
        if st.button("Save Preferences"):
            db.collection("users").document(username).update({"receive_forwarded_messages": receive_forwarded})
            st.success("Preferences saved successfully!")

        # Add a separator line
        st.markdown("---")  # Horizontal line for separation

        # Add forward message
        if len(st.session_state.messages) >= 2:
            last_user_message = st.session_state.messages[-2]["content"]
            last_assistant_message = st.session_state.messages[-1]["content"]

            users_docs = db.collection("users").stream()
            users = {doc.id: doc.to_dict() for doc in users_docs}

            recipient = st.selectbox("Forward to:", options=list(users.keys()), key="forward_recipient")
            if st.button("Forward", key="forward_button"):  
                if forward_message(last_user_message, last_assistant_message, recipient, username):
                    st.success(f"Message forwarded to {recipient}!")
                else:
                    st.warning(f"{recipient} has opted out of receiving forwarded messages.")

        if st.button("Clear Chat History"):
            st.session_state.messages = []
            save_messages_to_firebase(username, [])
            st.success("Chat history cleared!")
            st.rerun()

        # Add a separator line
        st.markdown("---")  # Horizontal line for separation

        if st.button("Logout"):
            update_user_logged_in_state(username, False)
            st.session_state.logged_in = False
            st.session_state.username = ""
            st.session_state.messages = []
            st.success("Logged out successfully!")
            st.rerun()