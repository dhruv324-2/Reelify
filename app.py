import os
from flask import Flask, session, request, redirect, render_template, url_for, flash
from flask_session import Session
import spotipy
from spotipy.oauth2 import SpotifyOAuth
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# --- App Initialization ---
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
db = SQLAlchemy()
login_manager = LoginManager()

# --- App Configuration ---
app.config['SECRET_KEY'] = 'a_very_secret_key_that_should_be_changed'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager.init_app(app)
Session(app)
login_manager.login_view = 'auth' 

# --- Spotify API Credentials ---
SPOTIPY_CLIENT_ID = '53076a76530540cb9800f68809c47305'
SPOTIPY_CLIENT_SECRET = 'e7179634b0014c70965d5f5b8316104e'
SPOTIPY_REDIRECT_URI = 'http://127.0.0.1:5000/callback'
SCOPE = 'playlist-modify-public'

# --- Database Model ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- Main Authentication Routes ---
@app.route('/')
def auth():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('auth.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        login_user(user, remember=True)
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid username or password')
        return redirect(url_for('auth'))

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    user = User.query.filter_by(username=username).first()
    if user:
        flash('Username already exists.')
        return redirect(url_for('auth'))
    email_exists = User.query.filter_by(email=email).first()
    if email_exists:
        flash('Email address already registered.')
        return redirect(url_for('auth'))
    
    new_user = User(username=username, email=email)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    
    login_user(new_user, remember=True)
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    logout_user()
    session.clear() 
    return redirect(url_for('auth'))

# --- Dashboard ---
@app.route('/dashboard')
def dashboard():
    if not current_user.is_authenticated:
        return redirect(url_for('auth'))
    instagram_connected = session.get('instagram_token_info') is not None
    return render_template('dashboard.html', user=current_user, instagram_connected=instagram_connected)

# --- Instagram Simulation Routes ---
@app.route('/instagram-connect')
def show_instagram_connect_page():
    if not current_user.is_authenticated:
        return redirect(url_for('auth'))
    return render_template('connect_instagram.html')

@app.route('/connect_instagram', methods=['POST'])
def connect_instagram():
    session['instagram_token_info'] = 'simulated_ig_token'
    return redirect(url_for('dashboard'))

# --- Route to Save Playlist Details from Form ---
@app.route('/save-details', methods=['POST'])
def save_playlist_details():
    if not current_user.is_authenticated:
        return redirect(url_for('auth'))
    
    playlist_base_name = request.form.get('playlist_name')
    if playlist_base_name:
        final_playlist_name = f"{playlist_base_name}'s Insta Playlist"
    else:
        final_playlist_name = f"{current_user.username}'s Insta Playlist"
    session['custom_playlist_name'] = final_playlist_name
    
    playlist_description = request.form.get('playlist_description', "")
    session['custom_playlist_description'] = playlist_description
    
    return redirect(url_for('connect'))

# --- Spotify Routes ---
@app.route("/connect")
def connect():
    if not current_user.is_authenticated:
        return redirect(url_for('auth')) 
    cache_path = os.path.join(basedir, 'instance', f".cache-{current_user.id}")
    if os.path.exists(cache_path):
        os.remove(cache_path)
        
    auth_manager = SpotifyOAuth(client_id=SPOTIPY_CLIENT_ID, client_secret=SPOTIPY_CLIENT_SECRET, redirect_uri=SPOTIPY_REDIRECT_URI, scope=SCOPE, cache_path=cache_path)
    return redirect(auth_manager.get_authorize_url())

@app.route("/callback")
def callback():
    cache_path = os.path.join(basedir, 'instance', f".cache-{current_user.id}")
    auth_manager = SpotifyOAuth(client_id=SPOTIPY_CLIENT_ID, client_secret=SPOTIPY_CLIENT_SECRET, redirect_uri=SPOTIPY_REDIRECT_URI, scope=SCOPE, cache_path=cache_path)
    code = request.args.get("code")
    token_info = auth_manager.get_access_token(code)
    session['token_info'] = token_info
    return redirect('/generate')

# --- Generate Playlist Route ---
@app.route("/generate")
def generate():
    token_info = session.get('token_info', None)
    if not token_info:
        flash('Could not get Spotify token. Please try connecting again.')
        return redirect('/dashboard')
    try:
        sp = spotipy.Spotify(auth=token_info['access_token'])
        user_id = sp.current_user()['id']
        simulated_reels_data = [
            {'title': 'Blinding Lights', 'artist': 'The Weeknd'},
            {'title': 'As It Was', 'artist': 'Harry Styles'},
            {'title': 'Levitating', 'artist': 'Dua Lipa'},
            {'title': 'Stay', 'artist': 'The Kid LAROI'},
            {'title': 'bad guy', 'artist': 'Billie Eilish'},
            {'title': 'Watermelon Sugar', 'artist': 'Harry Styles'}
        ]
        track_ids = []
        for song in simulated_reels_data:
            query = f"track:{song['title']} artist:{song['artist']}"
            results = sp.search(q=query, type='track', limit=1)
            if results['tracks']['items']:
                track_id = results['tracks']['items'][0]['id']
                track_ids.append(track_id)
        
        if not track_ids:
            flash('Could not find any songs from your Reels on Spotify.')
            return redirect('/dashboard')

        playlist_name = session.get('custom_playlist_name', f"{current_user.username}'s Insta Playlist")
        playlist_description = session.get('custom_playlist_description', "")

        new_playlist = sp.user_playlist_create(user=user_id, name=playlist_name, public=True, description=playlist_description)
        sp.playlist_add_items(playlist_id=new_playlist['id'], items=track_ids)
        
        session['new_playlist_name'] = new_playlist['name']
        session['new_playlist_url'] = new_playlist['external_urls']['spotify']
        return redirect(url_for('success'))
    except Exception as e:
        flash('An error occurred while creating the playlist. Please try again.')
        print(f"Error during playlist generation: {e}")
        return redirect('/dashboard')

@app.route('/success')
def success():
    if not current_user.is_authenticated:
        return redirect(url_for('auth'))
    
    playlist_name = session.get('new_playlist_name', 'Your New Playlist')
    playlist_url = session.get('new_playlist_url', '#')
    
    return render_template('success.html', playlist_name=playlist_name, playlist_url=playlist_url)

# --- Main Run Block ---
if __name__ == "__main__":
    with app.app_context():
        instance_path = os.path.join(basedir, 'instance')
        if not os.path.exists(instance_path):
            os.makedirs(instance_path)
        db.create_all()
    app.run(debug=True)

