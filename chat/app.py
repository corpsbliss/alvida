from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
db = SQLAlchemy(app)
socketio = SocketIO(app)
login_manager = LoginManager()
login_manager.init_app(app)

# Global variable to track server shutdown status
shutdown_flag = False

# Database models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room = db.Column(db.String(100))
    username = db.Column(db.String(150))
    message = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# To keep track of users in each room
room_users = {}

# User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Middleware to check for shutdown flag on every request
@app.before_request
def check_for_shutdown():
    global shutdown_flag
    if shutdown_flag and request.endpoint != 'shutdown':
        return redirect(url_for('shutdown'))

# Home route
@app.route('/')
@login_required
def index():
    return render_template('index.html', username=current_user.username)

# Shutdown page route
@app.route('/shutdown')
def shutdown():
    return render_template('shutdown.html')

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if username is already taken
        if User.query.filter_by(username=username).first():
            flash('Username is already taken, please choose another.')
            return redirect(url_for('register'))

        # Create new user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        # Validate user credentials
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Login failed. Please check your username and password.')

    return render_template('login.html')

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Chatroom route
@app.route('/chat/<room>')
@login_required
def chat(room):
    messages = Message.query.filter_by(room=room).order_by(Message.timestamp.asc()).all()
    return render_template('chat.html', username=current_user.username, room=room, messages=messages)

# When a user sends a message
@socketio.on('send_message')
def handle_send_message(data):
    room = data['room']
    msg = Message(room=room, username=data['username'], message=data['message'])
    db.session.add(msg)
    db.session.commit()
    emit('receive_message', {'message': data['message'], 'username': data['username']}, room=room)

# When a user joins a room
@socketio.on('join_room')
def handle_join_room(data):
    username = data['username']
    room = data['room']
    
    join_room(room)
    
    # Track the users in the room
    if room not in room_users:
        room_users[room] = set()
    room_users[room].add(username)
    
    emit('user_list', list(room_users[room]), room=room)
    emit('receive_message', {'message': f"{username} has joined the room.", 'username': 'System'}, room=room)

# When a user leaves a room
@socketio.on('leave_room')
def handle_leave_room(data):
    username = data['username']
    room = data['room']
    
    leave_room(room)
    
    # Remove the user from the room
    if room in room_users and username in room_users[room]:
        room_users[room].remove(username)

    emit('user_list', list(room_users[room]), room=room)
    emit('receive_message', {'message': f"{username} has left the room.", 'username': 'System'}, room=room)

# Trigger server shutdown by setting the flag
@socketio.on('trigger_shutdown')
def handle_trigger_shutdown(data):
    global shutdown_flag
    shutdown_flag = True
    emit('redirect', {'url': url_for('shutdown')}, broadcast=True)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables within application context
    socketio.run(app, debug=True)
