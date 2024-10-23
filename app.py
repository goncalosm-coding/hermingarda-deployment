import streamlit as st
import os
import re  # For email validation
from query_data import query_rag
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import credentials, firestore
import requests  # For REST API calls
import openai
import json
import subprocess

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
def get_user_from_firebase(email):
    doc_ref = db.collection("users").document(email)
    doc = doc_ref.get()
    if doc.exists:
        return doc.to_dict()  # Now includes username
    else:
        return None

# Check OpenAI API Key function
def check_openai_api_key(api_key):
    client = openai.OpenAI(api_key=api_key)
    try:
        client.models.list()
        return True
    except openai.APIError as e:
        # print(f"OpenAI API returned an API Error: {e}")
        return False
    except openai.APIConnectionError as e:
        # print(f"Failed to connect to OpenAI API: {e}")
        return False
    except openai.RateLimitError as e:
        # print(f"OpenAI API request exceeded rate limit: {e}")
        return False


# Firebase-specific functions
def save_user_to_firebase(username, email, api_key):
    user_data = {
        "username": username,
        "email": email,
        "api_key": api_key,
        "messages": [],
        "receive_forwarded_messages": True,
        "logged_in": False
    }
    db.collection("users").document(email).set(user_data)

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

    friendly_messages = {
                        "EMAIL_EXISTS": "This email is already registered. Please use another email or log in.",
                        "INVALID_EMAIL": "The email address is badly formatted. Please enter a valid email.",
                        "WEAK_PASSWORD": "Your password is too weak. Please use a stronger password.",
        }

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

                        # Only display the welcome message if there are no messages
                        if not st.session_state.messages:  # Check if message history is empty
                            st.session_state.messages.append({
                                "role": "assistant",
                                "content": f"👋 Hello, {user_data.get('username')}! How can I assist you today?"
                            })
                            save_messages_to_firebase(login_username, st.session_state.messages)

                        # Save the logged-in state
                        update_user_logged_in_state(login_username, True)
                        st.rerun()

                    else:
                        # Error handling for invalid login
                        # print("Error response from Firebase:", data)
                        
                        # Handle specific error messages based on Firebase response
                        error_message = data.get("error", {}).get("message", "")
                        if error_message == "INVALID_PASSWORD":
                            st.error("Incorrect password. Please try again.")
                        elif error_message == "EMAIL_NOT_FOUND":
                            st.error("No account found with this email. Please check your email or register.")
                        else:
                            st.error("Login failed. Please check your credentials and try again.")

                except Exception as e:
                    st.error(f"Error during login: {e}")
            else:
                st.error("Please enter a valid email address.")

    with tab2:
        st.subheader("Register")
        register_username = st.text_input("Username", key="register_username")
        register_email = st.text_input("Email", key="register_email")
        register_password = st.text_input("Password", type="password", key="register_password")
        register_api_key = st.text_input("API Key", type="password", key="register_api_key")

        if st.button("Register"):
            if not register_username:
                st.error("Please enter a username.")
            elif not is_valid_email(register_email):
                st.error("Please enter a valid email address.")
            else:
                if check_openai_api_key(register_api_key):
                    try:
                        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={os.getenv('FIREBASE_API_KEY')}"
                        payload = {
                            "email": register_email,
                            "password": register_password,
                            "returnSecureToken": True
                        }
                        response = requests.post(url, json=payload)
                        
                        if response.status_code == 200:
                            # Save user data in Firebase with username, API key, etc.
                            save_user_to_firebase(register_username, register_email, register_api_key)  # Modify to save username
                            st.success("Registration successful! You can now log in.")
                        else:
                            error_message = response.json().get("error", {}).get("message", "")
                            
                            # Get the error code before the colon (if exists)
                            error_code = error_message.split(" :")[0] if " :" in error_message else error_message
                            friendly_message = friendly_messages.get(error_code, "Error during registration.")
                            st.error(friendly_message)

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
        st.markdown("---")
        
        # Add forward message
        if len(st.session_state.messages) >= 2:
            last_user_message = st.session_state.messages[-2]["content"]
            last_assistant_message = st.session_state.messages[-1]["content"]

            users_docs = db.collection("users").stream()
            
            # Build a dictionary with email as the key and username as the value
            users = {doc.id: doc.to_dict().get("username", doc.id) for doc in users_docs}

            # Use the usernames in the selectbox
            recipient_username = st.selectbox("Forward to:", options=list(users.values()), key="forward_recipient")
            
            # Find the email associated with the selected username
            recipient_email = [email for email, username in users.items() if username == recipient_username][0]

            if st.button("Forward", key="forward_button"):  
                if forward_message(last_user_message, last_assistant_message, recipient_email, username):
                    st.success(f"Message forwarded to {recipient_username}")
                else:
                    st.warning(f"{recipient_username} has opted out of receiving forwarded messages.")


        # Database Management
        st.subheader("Database Management")

        # Button to trigger the population script
        if st.button("Update Database"):
            with st.spinner("Updating..."):
                result = subprocess.run(["python3", "populate_database.py"], capture_output=True, text=True)
                if result.returncode == 0:
                    st.success("Database populated successfully!")
                else:
                    st.error(f"Error occurred: {result.stderr}")

        if st.button("Clear Chat History"):
            st.session_state.messages = []
            save_messages_to_firebase(username, [])
            st.success("Chat history cleared!")
            st.rerun()

        # Add a separator line
        st.markdown("---")

        # Log out button
        if st.button("Log out"):
            st.session_state.logged_in = False
            update_user_logged_in_state(st.session_state.username, False)
            st.session_state.username = ""
            st.session_state.api_key = ""
            st.rerun()
