import json
import os
import uuid
from datetime import datetime, timezone
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sys

# Import Firebase Admin SDK components
import firebase_admin
from firebase_admin import credentials, firestore
from firebase_admin import auth


# --- Firebase Initialization ---
# For Render deployment, the service account key is mounted as a secret file
# at /etc/secrets/firebase_service_account_key.json
FIREBASE_SERVICE_ACCOUNT_KEY_PATH = "firebase_service_account_key.json"

try:
    # Initialize Firebase Admin SDK using the secure path on Render
    cred = credentials.Certificate(FIREBASE_SERVICE_ACCOUNT_KEY_PATH) # <--- THIS IS THE CORRECTED LINE
    firebase_admin.initialize_app(cred)
    db = firestore.client() # Get a Firestore client
    print("Firebase Admin SDK initialized successfully.")
except Exception as e:
    # Log the error but do not sys.exit(1) as Render handles service restarts
    print(f"Error initializing Firebase Admin SDK: {e}")
    print(f"Please ensure '{FIREBASE_SERVICE_ACCOUNT_KEY_PATH}' is correctly configured as a secret file on Render.")


# --- Flask Application Setup ---
app = Flask(__name__)
CORS(app) # Enable CORS for frontend communication during development


# --- API Endpoints ---

@app.route('/')
def serve_index():
    """Serves the main index.html file."""
    # For Render, static files are served from the current directory
    return send_from_directory(os.getcwd(), 'index.html')

@app.route('/<path:path>')
def serve_static_files(path):
    """Serves other static files (e.g., dashboard.html, chat.html)."""
    # For Render, static files are served from the current directory
    return send_from_directory(os.getcwd(), path)

@app.route('/register', methods=['POST'])
def register_user():
    """Handles user registration with Firebase Auth and Firestore."""
    data = request.json
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not all([email, username, password, confirm_password]):
        return jsonify({"message": "All fields are required!"}), 400

    if password != confirm_password:
        return jsonify({"message": "PASSWORDS DO NOT MATCH!!! TRY AGAIN"}), 400

    if len(password) < 6:
        return jsonify({"message": "Password must be at least 6 characters long."}), 400

    try:
        # 1. Check if username already exists in Firestore
        users_ref = db.collection('users')
        username_query = users_ref.where('username', '==', username).limit(1).get()
        if len(username_query) > 0:
            return jsonify({"message": "Username already taken."}), 409

        # 2. Create user in Firebase Authentication
        user_record = auth.create_user(email=email, password=password)
        user_id = user_record.uid # This is the unique Firebase UID

        # 3. Store additional user data (username, friends list) in Firestore
        user_data = {
            "email": email,
            "username": username,
            "password_for_backend_check": password, # For direct Python backend password check (less secure for production)
            "friends": [] # This will now store only established friendships
        }
        db.collection('users').document(user_id).set(user_data)

        print(f"Registered new user: {username} ({email}) with UID: {user_id}")
        return jsonify({"message": "Registration successful! You can now log in."}), 201

    except firebase_admin.auth.EmailAlreadyExistsError:
        return jsonify({"message": "Email already registered."}), 409
    except Exception as e:
        print(f"Error during registration: {e}")
        return jsonify({"message": f"An error occurred during registration: {e}"}), 500

@app.route('/login', methods=['POST'])
def login_user():
    """Handles user login by verifying credentials against Firestore."""
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not all([email, password]):
        return jsonify({"message": "Email and password are required!"}), 400

    try:
        # Find user by email in Firestore
        users_ref = db.collection('users')
        user_query = users_ref.where('email', '==', email).limit(1).get()

        if not user_query:
            return jsonify({"message": "Invalid email or password."}), 401

        user_doc = user_query[0]
        user_data = user_doc.to_dict()
        user_id = user_doc.id

        # Directly check password (as per user request - caution: less secure than production)
        if user_data.get('password_for_backend_check') != password:
            return jsonify({"message": "Invalid email or password."}), 401

        print(f"User logged in: {user_data['username']} (UID: {user_id})")
        return jsonify({
            "message": "Login successful!",
            "user_id": user_id,
            "username": user_data['username']
        }), 200

    except Exception as e:
        print(f"Error during login: {e}")
        return jsonify({"message": "An error occurred during login. Please try again."}), 500

# MODIFIED: Changed route to accept user_id as a path parameter
@app.route('/users/<user_id>', methods=['GET'])
def get_all_users(user_id): # user_id is now passed as an argument
    """Returns a list of all registered users (excluding the current user)."""
    # current_user_id = request.args.get('current_user_id') # No longer needed, as it's in path
    users_list = []
    try:
        users_ref = db.collection('users')
        users = users_ref.stream()

        for user_doc in users:
            user_data = user_doc.to_dict()
            # Use the user_id from the path parameter for filtering
            if user_doc.id != user_id: 
                users_list.append({
                    "id": user_doc.id, # Changed to 'id' to match frontend expectation
                    "username": user_data['username']
                })
        return jsonify({"users": users_list}), 200 # Wrapped in 'users' key as frontend expects
    except Exception as e:
        print(f"Error getting all users: {e}")
        return jsonify({"message": "Failed to load users."}), 500

@app.route('/friends/<user_id>', methods=['GET'])
def get_friends(user_id):
    """Returns the list of friends for a given user from Firestore."""
    try:
        user_doc = db.collection('users').document(user_id).get()
        if not user_doc.exists:
            return jsonify({"message": "User not found."}), 404

        user_data = user_doc.to_dict()
        friend_ids = user_data.get('friends', [])

        friend_usernames = []
        for friend_id in friend_ids:
            friend_info_doc = db.collection('users').document(friend_id).get()
            if friend_info_doc.exists:
                friend_info_data = friend_info_doc.to_dict()
                friend_usernames.append({
                    "id": friend_info_doc.id, # Changed to 'id' to match frontend expectation
                    "username": friend_info_data['username']
                })
        return jsonify({"friends": friend_usernames}), 200 # Wrapped in 'friends' key as frontend expects
    except Exception as e:
        print(f"Error getting friends for {user_id}: {e}")
        return jsonify({"message": "Failed to load friends."}), 500

# NEW: Send Friend Request
@app.route('/send_friend_request', methods=['POST'])
def send_friend_request():
    """Sends a friend request from sender_id to receiver_id."""
    data = request.json
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')

    if not all([sender_id, receiver_id]):
        return jsonify({"message": "Sender and receiver IDs are required."}), 400

    if sender_id == receiver_id:
        return jsonify({"message": "Cannot send friend request to yourself."}), 400

    try:
        sender_doc = db.collection('users').document(sender_id).get()
        receiver_doc = db.collection('users').document(receiver_id).get()

        if not sender_doc.exists or not receiver_doc.exists:
            return jsonify({"message": "Sender or receiver not found."}), 404

        sender_data = sender_doc.to_dict()
        receiver_data = receiver_doc.to_dict()

        # Check if already friends
        if receiver_id in sender_data.get('friends', []):
            return jsonify({"message": f"Already friends with {receiver_data['username']}."}), 409

        # Check for existing PENDING request (outgoing)
        existing_outgoing_request_query = db.collection('friend_requests') \
            .where('sender_id', '==', sender_id) \
            .where('receiver_id', '==', receiver_id) \
            .where('status', '==', 'pending') \
            .limit(1).get()
        if len(existing_outgoing_request_query) > 0:
            return jsonify({"message": "Friend request already sent to this user."}), 409

        # Check for existing PENDING request (incoming, if receiver already sent a request to sender)
        existing_incoming_request_query = db.collection('friend_requests') \
            .where('sender_id', '==', receiver_id) \
            .where('receiver_id', '==', sender_id) \
            .where('status', '==', 'pending') \
            .limit(1).get()
        if len(existing_incoming_request_query) > 0:
            return jsonify({"message": f"{receiver_data['username']} has already sent you a friend request. Please check your incoming requests."}), 409

        # Create new friend request
        request_data = {
            "sender_id": sender_id,
            "sender_username": sender_data['username'],
            "receiver_id": receiver_id,
            "receiver_username": receiver_data['username'],
            "status": "pending",
            "timestamp": firestore.SERVER_TIMESTAMP
        }
        db.collection('friend_requests').add(request_data)

        print(f"Friend request sent from {sender_data['username']} to {receiver_data['username']}")
        return jsonify({"message": "Friend request sent!"}), 200

    except Exception as e:
        print(f"Error sending friend request: {e}")
        return jsonify({"message": "An error occurred while sending friend request."}), 500

# MODIFIED: Changed route to match frontend expectation
@app.route('/friend_requests/<user_id>', methods=['GET']) # Changed from /friends/requests/<user_id>
def get_friend_requests(user_id):
    """Retrieves all incoming and outgoing friend requests for a given user."""
    incoming_requests = []
    outgoing_requests = []
    try:
        # Get incoming requests
        incoming_query = db.collection('friend_requests').where('receiver_id', '==', user_id).where('status', '==', 'pending').stream()
        for req_doc in incoming_query:
            req_data = req_doc.to_dict()
            incoming_requests.append({
                "request_id": req_doc.id,
                "sender_id": req_data['sender_id'],
                "sender_username": req_data['sender_username'],
                "timestamp": req_data['timestamp']
            })

        # Get outgoing requests
        outgoing_query = db.collection('friend_requests').where('sender_id', '==', user_id).where('status', '==', 'pending').stream()
        for req_doc in outgoing_query:
            req_data = req_doc.to_dict()
            outgoing_requests.append({
                "request_id": req_doc.id,
                "receiver_id": req_data['receiver_id'],
                "receiver_username": req_data['receiver_username'],
                "timestamp": req_data['timestamp']
            })

        return jsonify({
            "requests": incoming_requests, # Changed to 'requests' key as frontend expects incoming requests
            "outgoing": outgoing_requests
        }), 200
    except Exception as e:
        print(f"Error getting friend requests for {user_id}: {e}")
        return jsonify({"message": "Failed to load friend requests."}), 500

# NEW: Accept Friend Request (frontend expects to send sender_id, not request_id)
@app.route('/accept_friend_request', methods=['POST'])
def accept_friend_request():
    """Accepts a friend request and establishes mutual friendship."""
    data = request.json
    requester_id = data.get('requester_id') # The sender of the request
    accepter_id = data.get('accepter_id') # The user accepting the request (current user)

    if not all([requester_id, accepter_id]):
        return jsonify({"message": "Requester ID and accepter ID are required."}), 400

    if requester_id == accepter_id:
        return jsonify({"message": "Cannot accept request from yourself."}), 400

    try:
        # Find the pending request
        request_query = db.collection('friend_requests') \
            .where('sender_id', '==', requester_id) \
            .where('receiver_id', '==', accepter_id) \
            .where('status', '==', 'pending') \
            .limit(1).get()

        if not request_query:
            return jsonify({"message": "Pending friend request not found."}), 404

        request_doc = request_query[0]
        request_doc_ref = request_doc.reference
        request_data = request_doc.to_dict()

        # Update request status
        request_doc_ref.update({"status": "accepted", "accepted_at": firestore.SERVER_TIMESTAMP})

        # Add each user to the other's friends list (mutual friendship)
        db.collection('users').document(requester_id).update({
            'friends': firestore.ArrayUnion([accepter_id])
        })
        db.collection('users').document(accepter_id).update({
            'friends': firestore.ArrayUnion([requester_id])
        })

        print(f"Friend request accepted between {requester_id} and {accepter_id}.")
        return jsonify({"message": "Friend request accepted!"}), 200

    except Exception as e:
        print(f"Error accepting friend request: {e}")
        return jsonify({"message": "An error occurred while accepting friend request."}), 500

# NEW: Decline Friend Request (frontend expects to send sender_id, not request_id)
@app.route('/decline_friend_request', methods=['POST'])
def decline_friend_request():
    """Declines a friend request."""
    data = request.json
    requester_id = data.get('requester_id') # The sender of the request
    decliner_id = data.get('decliner_id') # The user declining the request (current user)

    if not all([requester_id, decliner_id]):
        return jsonify({"message": "Requester ID and decliner ID are required."}), 400

    if requester_id == decliner_id:
        return jsonify({"message": "Cannot decline request from yourself."}), 400

    try:
        # Find the pending request
        request_query = db.collection('friend_requests') \
            .where('sender_id', '==', requester_id) \
            .where('receiver_id', '==', decliner_id) \
            .where('status', '==', 'pending') \
            .limit(1).get()

        if not request_query:
            return jsonify({"message": "Pending friend request not found."}), 404

        request_doc = request_query[0]
        request_doc_ref = request_doc.reference
        request_data = request_doc.to_dict()

        # Update request status
        request_doc_ref.update({"status": "declined", "declined_at": firestore.SERVER_TIMESTAMP})

        print(f"Friend request declined between {requester_id} and {decliner_id}.")
        return jsonify({"message": "Friend request declined."}), 200

    except Exception as e:
        print(f"Error declining friend request: {e}")
        return jsonify({"message": "An error occurred while declining friend request."}), 500


@app.route('/remove_friend', methods=['POST']) # Changed route to match frontend expectation
def remove_friend():
    """Removes a friend from a user's friend list in Firestore and cancels related requests."""
    data = request.json
    user_id = data.get('user_id')
    friend_id = data.get('friend_id')

    try:
        user_ref = db.collection('users').document(user_id)
        friend_ref = db.collection('users').document(friend_id)

        user_doc = user_ref.get()
        friend_doc = friend_ref.get()

        if not user_doc.exists or not friend_doc.exists:
            return jsonify({"message": "User or friend not found."}), 404

        user_data = user_doc.to_dict()
        friend_data = friend_doc.to_dict()

        if friend_id not in user_data.get('friends', []):
            return jsonify({"message": "User is not in your friend list."}), 400

        # Remove friend from user's list
        # CORRECTED: Changed ArrayUnion to ArrayRemove and receiver_id to friend_id
        db.collection('users').document(user_id).update({
            'friends': firestore.ArrayRemove([friend_id])
        })
        # Remove user from friend's list as well for mutual friendship
        db.collection('users').document(friend_id).update({
            'friends': firestore.ArrayRemove([user_id])
        })

        # NEW: Find and update any related friend_request documents to 'cancelled' or 'removed'
        # This covers both directions (A->B and B->A) if they were previously friends via a request
        related_requests = db.collection('friend_requests').where(
            firestore.FieldFilter('sender_id', 'in', [user_id, friend_id])
        ).where(
            firestore.FieldFilter('receiver_id', 'in', [user_id, friend_id])
        ).get()

        for req_doc in related_requests:
            req_data = req_doc.to_dict()
            # Only update if the status is not already declined/cancelled (might be 'accepted')
            if req_data.get('status') in ['pending', 'accepted']:
                db.collection('friend_requests').document(req_doc.id).update({
                    "status": "cancelled_by_unfriend",
                    "cancelled_at": firestore.SERVER_TIMESTAMP
                })
                print(f"Updated friend request {req_doc.id} status to 'cancelled_by_unfriend' due to unfriend action.")


        print(f"User {user_data['username']} removed {friend_data['username']} from friends.")
        return jsonify({"message": "Friend removed successfully!"}), 200
    except Exception as e:
        print(f"Error removing friend: {e}")
        return jsonify({"message": "An error occurred while removing friend."}), 500

# NEW: Endpoint to get unread message counts for a user
@app.route('/get_unread_counts/<user_id>', methods=['GET'])
def get_unread_counts(user_id):
    """
    Calculates and returns the number of unread messages for each friend of the given user.
    Unread messages are those sent by a friend *after* the user's last_read_timestamp for that chat.
    """
    unread_counts = {}
    try:
        # Get the current user's friends
        user_doc = db.collection('users').document(user_id).get()
        if not user_doc.exists:
            return jsonify({"message": "User not found."}), 404
        friend_ids = user_doc.to_dict().get('friends', [])

        for friend_id in friend_ids:
            chat_id = '_'.join(sorted([user_id, friend_id]))
            
            # Get the last read timestamp for this chat from the current user's perspective
            # Path: user_chat_metadata/{user_id}/chat_partners/{friend_id}
            last_read_doc_ref = db.collection('user_chat_metadata').document(user_id).collection('chat_partners').document(friend_id)
            last_read_doc = last_read_doc_ref.get()
            
            # Initialize last_read_timestamp to a very old but valid datetime
            # This ensures that if no last_read_timestamp is found, all messages will be counted as unread.
            last_read_timestamp_dt = datetime(1, 1, 1, tzinfo=timezone.utc) # Year 1, Jan 1, UTC
            
            if last_read_doc.exists:
                last_read_timestamp_data = last_read_doc.to_dict().get('last_read_timestamp')
                if last_read_timestamp_data and isinstance(last_read_timestamp_data, db.Timestamp): # Use db.Timestamp
                    last_read_timestamp_dt = last_read_timestamp_data.astimezone(timezone.utc) # Convert to datetime object in UTC
            
            # Query messages in this chat sent by the friend
            # that are newer than the last_read_timestamp_dt
            messages_query = db.collection('chats').document(chat_id).collection('messages') \
                .where('sender_id', '==', friend_id) \
                .where('timestamp', '>', last_read_timestamp_dt) \
                .order_by('timestamp') # Ensure ordering for comparison

            unread_count = 0
            for msg_doc in messages_query.stream():
                unread_count += 1
            
            unread_counts[friend_id] = unread_count

        return jsonify({"unread_counts": unread_counts}), 200

    except Exception as e:
        print(f"Error getting unread counts for user {user_id}: {e}")
        return jsonify({"message": "Failed to get unread counts."}), 500


@app.route('/chat_history/<user1_id>/<user2_id>', methods=['GET'])
def get_chat_history(user1_id, user2_id):
    """
    Retrieves chat messages between two users from Firestore and updates the last_read_timestamp
    for user1 in the chat with user2.
    """
    chat_id = '_'.join(sorted([user1_id, user2_id]))
    messages = []
    
    # Initialize latest_message_timestamp to a very old but valid datetime
    latest_message_timestamp_dt = datetime(1, 1, 1, tzinfo=timezone.utc) # Year 1, Jan 1, UTC

    try:
        messages_ref = db.collection('chats').document(chat_id).collection('messages').order_by('timestamp').stream()
        for msg_doc in messages_ref:
            msg_data = msg_doc.to_dict()
            messages.append(msg_data)
            # Keep track of the latest message timestamp
            # Ensure it's a Firestore Timestamp object for setting
            if isinstance(msg_data['timestamp'], db.Timestamp): # Use db.Timestamp
                latest_message_timestamp_dt = msg_data['timestamp']
            else:
                # If it's not a Firestore Timestamp, convert it (e.g., if it's a Python datetime)
                latest_message_timestamp_dt = db.Timestamp.from_datetime(msg_data['timestamp'].astimezone(timezone.utc)) # Use db.Timestamp.from_datetime


        # Update the last_read_timestamp for user1 in their chat metadata with user2
        # Path: user_chat_metadata/{user1_id}/chat_partners/{user2_id}
        user1_chat_metadata_ref = db.collection('user_chat_metadata').document(user1_id).collection('chat_partners').document(user2_id)
        user1_chat_metadata_ref.set({
            'last_read_timestamp': latest_message_timestamp_dt
        }, merge=True) # Use merge=True to create if not exists, or update if exists

        return jsonify(messages), 200
    except Exception as e:
        print(f"Error getting chat history for {chat_id}: {e}")
        return jsonify({"message": "Failed to load chat history."}), 500

@app.route('/send_message', methods=['POST'])
def send_message():
    """Sends a new message between two users to Firestore."""
    data = request.json
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    message_text = data.get('message')

    if not all([sender_id, receiver_id, message_text]):
        return jsonify({"message": "Sender, receiver, and message are required."}), 400

    try:
        sender_user_doc = db.collection('users').document(sender_id).get()
        receiver_user_doc = db.collection('users').document(receiver_id).get()

        if not sender_user_doc.exists or not receiver_user_doc.exists:
            return jsonify({"message": "Sender or receiver not found."}), 404

        sender_user_data = sender_user_doc.to_dict()
        receiver_user_data = receiver_user_doc.to_dict()

        if receiver_id not in sender_user_data.get('friends', []):
            return jsonify({"message": "You can only chat with your friends. Add them first!"}), 403

        chat_id = '_'.join(sorted([sender_id, receiver_id]))

        new_message = {
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "message": message_text,
            "timestamp": firestore.SERVER_TIMESTAMP # Use Firestore server timestamp
        }

        db.collection('chats').document(chat_id).collection('messages').add(new_message)

        print(f"Message from {sender_user_data['username']} to {receiver_user_data['username']}: {message_text}")
        return jsonify({"message": "Message sent successfully!"}), 201
    except Exception as e:
        print(f"Error sending message: {e}")
        return jsonify({"message": "An error occurred while sending message."}), 500

# NEW: Logout Route
@app.route('/logout', methods=['POST'])
def logout_user():
    """Handles user logout. For now, it's a simple confirmation."""
    # In a real app, you might invalidate a token or clear server-side session here.
    # Since we're using sessionStorage on the frontend, this primarily confirms the action.
    user_id = request.json.get('user_id')
    print(f"User {user_id} requested logout.")
    return jsonify({"message": "Logged out successfully!"}), 200

if __name__ == '__main__':
    app.run(debug=True, port=50)