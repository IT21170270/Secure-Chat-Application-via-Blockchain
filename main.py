import base64
from datetime import datetime
import bcrypt
import ipfshttpclient
from bson import ObjectId
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_socketio import SocketIO, emit, join_room
from pymongo import MongoClient
from werkzeug.utils import secure_filename
import ipfshttpclient

import blockchain

app = Flask(__name__)
app.secret_key = 'HJIKS*&JIKNS&*(Nnjkhsagyuda7JNHKJ@#$'
socketio = SocketIO(app)

# MongoDB setup

client = MongoClient('mongodb+srv://nimeshmaduranga274:FX8s36e9SF7VbSF8@cluster0.rqdfvy0.mongodb.net/')  # Replace with your MongoDB connection string
db = client['BlockChain']
users = db.users
chatlists = db.chats

# IPFS setup
ipfs_client = ipfshttpclient.connect()

def upload_to_ipfs(data):
    res = ipfs_client.add_bytes(data)
    return res

def get_from_ipfs(hash):
    data = ipfs_client.cat(hash)
    return data

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm-password']

    if password != confirm_password:
        return "Passwords do not match!", 400

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Handling the profile picture
    profile_picture = request.files['profile-picture']
    if profile_picture and profile_picture.filename != '':
        filename = secure_filename(profile_picture.filename)
        mimetype = profile_picture.mimetype
        if not mimetype.startswith('image'):
            return "File must be an image", 400

        img_bytes = profile_picture.read()
        encoded_string = base64.b64encode(img_bytes).decode('utf-8')
        image_uri = f"data:{mimetype};base64,{encoded_string}"
    else:
        image_uri = None  # No image provided

    key, account = blockchain.create_account()

    user_data = {
        "username": username,
        "email": email,
        "password": hashed_password,  # Store the hashed password
        "profile_picture_uri": image_uri,
        "account": account,
        "key": key
    }

    # Insert the user data into MongoDB
    users.insert_one(user_data)

    return jsonify({'status': 'success', 'message': 'Registration successful! Redirecting...'}), 200

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = users.find_one({"email": email})

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session['user_id'] = str(user['_id'])  # Store user's ID in session
            return jsonify({'message': 'Login successful', 'redirect': url_for('dashboard')})
        else:
            return jsonify({'error': 'Invalid email or password'}), 401

    return render_template('index.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove the user_id from session
    return redirect(url_for('home'))  # Redirect to the home page or login page

@app.route('/home')
def dashboard():
    if 'user_id' in session:
        user = users.find_one({"_id": ObjectId(session['user_id'])})
        friend_ids = user.get('friends', [])
        return render_template('dashboard.html', user=user, friends=users.find({"_id": {"$in": friend_ids}}))
    else:
        return redirect(url_for('login'))

@app.route('/colleague')
def colleague():
    if 'user_id' in session:
        current_user_id = session['user_id']
        user = users.find_one({"_id": ObjectId(current_user_id)})
        if not user:
            # If no user is found, possibly handle this more gracefully
            return redirect(url_for('login'))

        friend_ids = user.get('friends', [])  # Retrieve list of friend IDs from the user document
        exclusion_list = [ObjectId(current_user_id)] + [ObjectId(friend_id) for friend_id in friend_ids]  # Include current user and friends to exclude

        users_list = users.find({"_id": {"$nin": exclusion_list}})
        request_users = users.find({"_id": {"$in": user.get('requests', [])}}) if 'requests' in user else []

        return render_template('colleague.html', user=user, users=users_list, requests=request_users, friends=users.find({"_id": {"$in": friend_ids}}))
    else:
        return redirect(url_for('login'))

@app.route('/send_request/<recipient_id>', methods=['POST'])
def send_request(recipient_id):
    if 'user_id' not in session:
        return jsonify({'error': 'User not logged in'}), 403

    current_user_id = session['user_id']
    if current_user_id == recipient_id:
        return jsonify({'error': 'Cannot send request to self'}), 400

    recipient_user = users.find_one({"_id": ObjectId(recipient_id)})

    # Check if the current user's ID is already in the recipient's requests list
    if ObjectId(current_user_id) in recipient_user.get('requests', []):
        return jsonify({'message': 'Request already sent'}), 200

    users.update_one(
        {"_id": ObjectId(recipient_id)},
        {"$addToSet": {"requests": ObjectId(current_user_id)}}
    )

    return jsonify({'message': 'Request sent successfully'}), 200

@app.route('/respond_request/<user_id>', methods=['POST'])
def respond_request(user_id):
    if 'user_id' not in session:
        return jsonify({'error': 'User not logged in'}), 403

    current_user_id = session['user_id']
    accepted = request.json.get('accepted')

    try:
        if accepted:
            # Add each user to the other's 'friends' list using $addToSet to avoid duplicates
            users.update_one(
                {"_id": ObjectId(current_user_id)},
                {"$addToSet": {"friends": ObjectId(user_id)}}
            )
            users.update_one(
                {"_id": ObjectId(user_id)},
                {"$addToSet": {"friends": ObjectId(current_user_id)}}
            )
            message = "Friend added successfully"
        else:
            message = "Request declined"

        # Remove the requester's ID from the current user's requests in either case
        users.update_one(
            {"_id": ObjectId(current_user_id)},
            {"$pull": {"requests": ObjectId(user_id)}}
        )

        return jsonify({'message': message}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/remove_colleague/<colleague_id>', methods=['POST'])
def remove_colleague(colleague_id):
    current_user_id = session['user_id']
    if not current_user_id:
        return jsonify({'error': 'User ID missing'}), 400

    try:
        # Assuming each user has a 'friends' list in their document
        users.update_one({"_id": ObjectId(current_user_id)}, {"$pull": {"friends": ObjectId(colleague_id)}})
        users.update_one({"_id": ObjectId(colleague_id)}, {"$pull": {"friends": ObjectId(current_user_id)}})
        return jsonify({'message': 'Colleague removed successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/chat/<friend_id>')
def chat(friend_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = users.find_one({"_id": ObjectId(user_id)})
    friend = users.find_one({'_id': ObjectId(friend_id)})
    if not friend:
        return "Friend not found", 404

    messages = get_messages(user_id, friend_id)
    return render_template('chat_.html', friend=friend, messages=messages, user=user)

def get_messages(user_id, friend_id):
    messages = list(chatlists.find({
        '$or': [
            {'sender_id': ObjectId(user_id), 'receiver_id': ObjectId(friend_id)},
            {'sender_id': ObjectId(friend_id), 'receiver_id': ObjectId(user_id)}
        ]
    }).sort('date', 1))  # Assuming you have a 'date' field to sort by

    # Verify each message with the blockchain
    for message in messages:
        transaction_id = message.get('blockchain_transaction_id')
        if transaction_id:
            # Fetch the transaction from the blockchain
            blockchain_transaction = blockchain.fetch_transaction(transaction_id)
            # Assume blockchain_transaction contains fields like 'hash' that you can compare
            expected_hash = blockchain.hash_function(message['message'] + str(message.get('file_content', '')))
            if blockchain_transaction['hash'] != expected_hash:
                # If the hash doesn't match, it indicates tampering
                message['tampered'] = True
            else:
                message['tampered'] = False

        # Retrieve file content from IPFS if available
        if 'file_content' in message:
            ipfs_hash = message['file_content']
            message['file_content'] = get_from_ipfs(ipfs_hash)

    return messages

@app.template_filter('get_icon_class')
def get_icon_class(file_extension):
    """Returns the font-awesome class based on the file extension."""
    if file_extension in ['png', 'jpg', 'jpeg', 'gif']:
        return 'fas fa-file-image'
    elif file_extension in ['pdf']:
        return 'fas fa-file-pdf'
    elif file_extension in ['doc', 'docx']:
        return 'fas fa-file-word'
    elif file_extension in ['xls', 'xlsx']:
        return 'fas fa-file-excel'
    elif file_extension in ['txt']:
        return 'fas fa-file-alt'
    else:
        return 'fas fa-file'

@socketio.on('send_message')
def handle_send_message(data):
    sender_id = session.get('user_id')
    receiver_id = data['friend_id']
    message_text = data['message']
    file = data.get('file')
    file_name = data.get('fileName')

    sender = users.find_one({"_id": ObjectId(sender_id)})
    receiver = users.find_one({"_id": ObjectId(receiver_id)})

    key = sender['key']
    address = receiver['account']

    if file:
        file_content = base64.b64encode(file).decode('utf-8')  # Ensure file is bytes
        file_hash = blockchain.hash_function(file_content)  # Generate a hash of the file content

        # Store file content on IPFS
        ipfs_hash = upload_to_ipfs(file)
    else:
        file_content = None
        file_hash = None
        ipfs_hash = None

    # Create a blockchain transaction
    transaction = blockchain.create_transaction(sender_id, receiver_id, message_text, file_hash, datetime.now(), key, address)

    # Commit the transaction to the blockchain and get the transaction ID
    transaction_id = blockchain.commit_transaction(transaction)

    # Store in MongoDB with reference to IPFS hash
    chat_message = {
        'sender_id': ObjectId(sender_id),
        'receiver_id': ObjectId(receiver_id),
        'date': datetime.now(),
        'message': message_text,
       'file_content': ipfs_hash,  # Store IPFS hash instead of the actual content
        'file_name': file_name if file else None,
        'blockchain_transaction_id': transaction_id
    }
    chatlists.insert_one(chat_message)

    emit('receive_message', {
        'sender_id': str(sender_id),
        'message': message_text,
        'file_name': file_name,
        'file_content': file_content  # Sending file content directly for immediate display
    }, room=receiver_id)
    emit('receive_message', {
        'sender_id': str(sender_id),
        'message': message_text,
        'file_name': file_name,
        'file_content': file_content
    }, room=sender_id)

@socketio.on('join')
def on_join(data):
    room = session.get('user_id')
    join_room(room)
    emit('status', {'msg': 'One of your friends joined the chat.'}, room=room)

if __name__ == '__main__':
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
