import json
import os
import uuid
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sys

# Import Firebase Admin SDK components
import firebase_admin
from firebase_admin import credentials, firestore, auth

# --- Firebase Initialization ---
# For Render deployment, the service account key is mounted as a secret file
# at /etc/secrets/firebase_service_account_key.json
FIREBASE_SERVICE_ACCOUNT_KEY_PATH = "firebase_service_acCount_key.json"

try:
    # Initialize Firebase Admin SDK using the secure path on Render
    cred = credentials.Certificate(FIREBASE_SERVICE_ACCOUNT_KEY_PATH)
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

        # Directly check password (as per user request - caution: less secure than Firebase Auth direct client-side login)
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

@app.route('/users', methods=['GET'])
def get_all_users():
    """Returns a list of all registered users (excluding the current user)."""
    current_user_id = request.args.get('current_user_id')
    users_list = []
    try:
        users_ref = db.collection('users')
        users = users_ref.stream()

        for user_doc in users:
            user_data = user_doc.to_dict()
            if user_doc.id != current_user_id:
                users_list.append({
                    "user_id": user_doc.id,
                    "username": user_data['username']
                })
        return jsonify(users_list), 200
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
                    "user_id": friend_info_doc.id,
                    "username": friend_info_data['username']
                })
        return jsonify(friend_usernames), 200
    except Exception as e:
        print(f"Error getting friends for {user_id}: {e}")
        return jsonify({"message": "Failed to load friends."}), 500

# NEW: Send Friend Request
@app.route('/friends/send_request', methods=['POST'])
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

# NEW: Get Friend Requests (Incoming and Outgoing)
@app.route('/friends/requests/<user_id>', methods=['GET'])
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
            "incoming": incoming_requests,
            "outgoing": outgoing_requests
        }), 200
    except Exception as e:
        print(f"Error getting friend requests for {user_id}: {e}")
        return jsonify({"message": "Failed to load friend requests."}), 500

# NEW: Accept Friend Request
@app.route('/friends/accept_request', methods=['POST'])
def accept_friend_request():
    """Accepts a friend request and establishes mutual friendship."""
    data = request.json
    request_id = data.get('request_id')
    acceptor_id = data.get('acceptor_id') # The user accepting the request

    if not all([request_id, acceptor_id]):
        return jsonify({"message": "Request ID and acceptor ID are required."}), 400

    try:
        request_doc_ref = db.collection('friend_requests').document(request_id)
        request_doc = request_doc_ref.get()

        if not request_doc.exists:
            return jsonify({"message": "Friend request not found."}), 404

        request_data = request_doc.to_dict()
        sender_id = request_data['sender_id']
        receiver_id = request_data['receiver_id']

        # Ensure the acceptor is the actual receiver of the request
        if acceptor_id != receiver_id:
            return jsonify({"message": "You are not authorized to accept this request."}), 403
        
        # Ensure the request is still pending
        if request_data.get('status') != 'pending':
            return jsonify({"message": "This friend request is no longer pending."}), 400

        # Update request status
        request_doc_ref.update({"status": "accepted", "accepted_at": firestore.SERVER_TIMESTAMP})

        # Add each user to the other's friends list (mutual friendship)
        db.collection('users').document(sender_id).update({
            'friends': firestore.ArrayUnion([receiver_id])
        })
        db.collection('users').document(receiver_id).update({
            'friends': firestore.ArrayUnion([sender_id])
        })

        print(f"Friend request {request_id} accepted between {sender_id} and {receiver_id}.")
        return jsonify({"message": "Friend request accepted!"}), 200

    except Exception as e:
        print(f"Error accepting friend request: {e}")
        return jsonify({"message": "An error occurred while accepting friend request."}), 500

# NEW: Decline Friend Request
@app.route('/friends/decline_request', methods=['POST'])
def decline_friend_request():
    """Declines a friend request."""
    data = request.json
    request_id = data.get('request_id')
    decliner_id = data.get('decliner_id') # The user declining the request

    if not all([request_id, decliner_id]):
        return jsonify({"message": "Request ID and decliner ID are required."}), 400

    try:
        request_doc_ref = db.collection('friend_requests').document(request_id)
        request_doc = request_doc_ref.get()

        if not request_doc.exists:
            return jsonify({"message": "Friend request not found."}), 404

        request_data = request_doc.to_dict()
        receiver_id = request_data['receiver_id']

        # Ensure the decliner is the actual receiver of the request
        if decliner_id != receiver_id:
            return jsonify({"message": "You are not authorized to decline this request."}), 403
            
        # Ensure the request is still pending
        if request_data.get('status') != 'pending':
            return jsonify({"message": "This friend request is no longer pending."}), 400

        # Update request status
        request_doc_ref.update({"status": "declined", "declined_at": firestore.SERVER_TIMESTAMP})

        print(f"Friend request {request_id} declined.")
        return jsonify({"message": "Friend request declined."}), 200

    except Exception as e:
        print(f"Error declining friend request: {e}")
        return jsonify({"message": "An error occurred while declining friend request."}), 500


@app.route('/friends/remove', methods=['POST'])
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

@app.route('/chat_history/<user1_id>/<user2_id>', methods=['GET'])
def get_chat_history(user1_id, user2_id):
    """Retrieves chat messages between two users from Firestore."""
    chat_id = '_'.join(sorted([user1_id, user2_id]))
    messages = []
    try:
        messages_ref = db.collection('chats').document(chat_id).collection('messages').order_by('timestamp').stream()
        for msg_doc in messages_ref:
            messages.append(msg_doc.to_dict())
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

if __name__ == '__main__':
    app.run(debug=True, port=5000)
