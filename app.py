from groq import Groq
from dotenv import load_dotenv
import os

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

from flask import Flask, render_template, request, redirect, url_for, session, g, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'database.db')

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "replace_this_with_a_random_secret_in_production")

# --- Database helpers ---

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db
@app.cli.command("initdb")
def initdb():
    db = sqlite3.connect(DB_PATH)
    cursor = db.cursor()

    cursor.executescript("""
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS doubts;
        DROP TABLE IF EXISTS replies;
        DROP TABLE IF EXISTS videos;
        DROP TABLE IF EXISTS meetings;

        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT
        );

        CREATE TABLE doubts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            user_id INTEGER,
            created_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE replies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doubt_id INTEGER,
            user_id INTEGER,
            content TEXT NOT NULL,
            created_at TEXT,
            FOREIGN KEY(doubt_id) REFERENCES doubts(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE videos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER,
            title TEXT,
            video_url TEXT,
            description TEXT,
            created_at TEXT,
            FOREIGN KEY(teacher_id) REFERENCES users(id)
        );

        CREATE TABLE meetings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER,
            link TEXT,
            time TEXT,
            topic TEXT,
            created_at TEXT,
            FOREIGN KEY(teacher_id) REFERENCES users(id)
        );
    """)

    db.commit()
    db.close()
    print("Database initialized with correct schema!")

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def column_exists(table, column):
    db = get_db()
    cur = db.execute("PRAGMA table_info(%s)" % table)
    cols = [r["name"] for r in cur.fetchall()]
    return column in cols

def init_db():
    db = get_db()
    cur = db.cursor()
    # users table (ensure role column exists)
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT
        )
    ''')
    # add role column if missing
    if not column_exists('users', 'role'):
        try:
            cur.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'student'")
        except Exception:
            pass

    # doubts table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS doubts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            user_id INTEGER,
            created_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    # replies table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS replies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doubt_id INTEGER,
            user_id INTEGER,
            content TEXT NOT NULL,
            created_at TEXT,
            FOREIGN KEY(doubt_id) REFERENCES doubts(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    # videos table (teacher uploaded resources — stored as URL for now)
    cur.execute('''
        CREATE TABLE IF NOT EXISTS videos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER,
            title TEXT,
            video_url TEXT,
            description TEXT,
            created_at TEXT,
            FOREIGN KEY(teacher_id) REFERENCES users(id)
        )
    ''')

    # meetings table (teacher scheduled meetings)
    cur.execute('''
        CREATE TABLE IF NOT EXISTS meetings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER,
            link TEXT,
            time TEXT,
            topic TEXT,
            created_at TEXT,
            FOREIGN KEY(teacher_id) REFERENCES users(id)
        )
    ''')

    db.commit()

# initialize DB at start
with app.app_context():
    init_db()

# --- Auth helpers ---

def current_user():
    if 'user_id' in session:
        db = get_db()
        cur = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
        return cur.fetchone()
    return None

def require_login():
    if not current_user():
        flash('Login required')
        return redirect(url_for('login'))

def require_role(role):
    user = current_user()
    if not user:
        flash('Login required')
        return redirect(url_for('login'))
    if user['role'] != role:
        flash('Unauthorized access')
        # redirect to their dashboard or index
        return redirect(url_for('dashboard'))

# --- Routes ---

@app.route('/')
def index():
    db = get_db()
    cur = db.execute('''
        SELECT d.*, u.username 
        FROM doubts d 
        LEFT JOIN users u ON d.user_id = u.id 
        ORDER BY d.created_at DESC
    ''')
    doubts = cur.fetchall()
    return render_template('index.html', doubts=doubts, user=current_user())

@app.route('/dashboard')
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    if user['role'] == 'teacher':
        return redirect(url_for('teacher_dashboard'))
    else:
        return redirect(url_for('student_dashboard'))

@app.route('/ai_suggest/<int:doubt_id>')
def ai_suggest(doubt_id):
    db = get_db()
    cur = db.execute('SELECT * FROM doubts WHERE id = ?', (doubt_id,))
    doubt = cur.fetchone()

    if not doubt:
        flash('Doubt not found')
        return redirect(url_for('index'))

    prompt = f"""
    A student has asked the following doubt:

    Title: {doubt['title']}
    Description: {doubt['description']}

    Provide a very clear, short explanation suitable for a student.
    """

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}]
        )
        ai_answer = response.choices[0].message.content
    except Exception as e:
        ai_answer = f"AI could not generate an answer (Groq error: {str(e)})"

    return render_template(
        "ai_answer.html",
        doubt=doubt,
        ai_answer=ai_answer,
        user=current_user()
    )

# --- Auth routes ---

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        role = request.form.get('role', 'student').strip().lower()
        if role not in ('student', 'teacher'):
            role = 'student'

        if not username or not password:
            flash('Please provide both username and password')
            return redirect(url_for('signup'))
        db = get_db()
        try:
            db.execute(
                'INSERT INTO users (username, password_hash, created_at, role) VALUES (?, ?, ?, ?)',
                (username, generate_password_hash(password), datetime.utcnow().isoformat(), role)
            )
            db.commit()
            flash('Account created. Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already taken. Choose another.')
            return redirect(url_for('signup'))

    return render_template('signup.html', user=current_user())

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        db = get_db()
        cur = db.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cur.fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            flash('Logged in successfully')

            # ROLE-BASED REDIRECT FIX
            if user['role'] == 'teacher':
                return redirect(url_for('teacher_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))

        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))

    return render_template('login.html', user=current_user())


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out')
    return redirect(url_for('index'))

# ----- Doubts (unchanged) -----

@app.route('/post', methods=['GET', 'POST'])
def post_doubt():
    user = current_user()
    if not user:
        flash('You must be logged in to post a doubt')
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        if not title or not description:
            flash('Title and description are required')
            return redirect(url_for('post_doubt'))
        db = get_db()
        db.execute('INSERT INTO doubts (title, description, user_id, created_at) VALUES (?, ?, ?, ?)',
                   (title, description, user['id'], datetime.utcnow().isoformat()))
        db.commit()
        flash('Doubt posted')
        return redirect(url_for('index'))

    return render_template('post_doubt.html', user=user)

@app.route('/doubt/<int:doubt_id>', methods=['GET'])
def view_doubt(doubt_id):
    db = get_db()
    cur = db.execute('SELECT d.*, u.username FROM doubts d LEFT JOIN users u ON d.user_id = u.id WHERE d.id = ?', (doubt_id,))
    doubt = cur.fetchone()
    if not doubt:
        flash('Doubt not found')
        return redirect(url_for('index'))
    cur = db.execute('SELECT r.*, u.username FROM replies r LEFT JOIN users u ON r.user_id = u.id WHERE r.doubt_id = ? ORDER BY r.created_at ASC', (doubt_id,))
    replies = cur.fetchall()
    return render_template('view_doubt.html', doubt=doubt, replies=replies, user=current_user())

@app.route('/reply/<int:doubt_id>', methods=['POST'])
def reply(doubt_id):
    user = current_user()
    if not user:
        flash('You must be logged in to reply')
        return redirect(url_for('login'))
    content = request.form['content'].strip()
    if not content:
        flash('Reply cannot be empty')
        return redirect(url_for('view_doubt', doubt_id=doubt_id))
    db = get_db()
    db.execute('INSERT INTO replies (doubt_id, user_id, content, created_at) VALUES (?, ?, ?, ?)',
               (doubt_id, user['id'], content, datetime.utcnow().isoformat()))
    db.commit()
    flash('Reply posted')
    return redirect(url_for('view_doubt', doubt_id=doubt_id))

# ----- Edit/Delete Doubts & Replies (unchanged) -----
# (You can keep your existing handlers — they will continue to work.)
# ... (keep code from your previous implementation)
# To avoid duplication, I'm not pasting them again here; the earlier functions
# such as edit_doubt, delete_doubt, edit_reply, delete_reply, and profile remain valid.

# ----- Teacher / Student Dashboards & Tools -----

@app.route('/teacher/dashboard')
def teacher_dashboard():
    user = current_user()
    if not user:
        flash('Login required')
        return redirect(url_for('login'))
    if user['role'] != 'teacher':
        flash('Unauthorized - teacher accounts only')
        return redirect(url_for('dashboard'))
    db = get_db()
    # load teacher videos and meetings
    videos = db.execute('SELECT * FROM videos WHERE teacher_id = ? ORDER BY created_at DESC', (user['id'],)).fetchall()
    meetings = db.execute('SELECT * FROM meetings WHERE teacher_id = ? ORDER BY created_at DESC', (user['id'],)).fetchall()
    # also show pending doubts to respond to
    doubts = db.execute('SELECT d.*, u.username FROM doubts d LEFT JOIN users u ON d.user_id = u.id ORDER BY d.created_at DESC').fetchall()
    return render_template('teacher_dashboard.html', user=user, videos=videos, meetings=meetings, doubts=doubts)



@app.route('/student/dashboard')
def student_dashboard():
    user = current_user()
    if not user:
        flash("Login required")
        return redirect(url_for("login"))

    if user["role"] != "student":
        flash("Unauthorized - students only")
        return redirect(url_for("dashboard"))

    db = get_db()

    # Load doubts
    doubts = db.execute('''
        SELECT d.*, u.username 
        FROM doubts d 
        LEFT JOIN users u ON d.user_id = u.id
        ORDER BY d.created_at DESC
    ''').fetchall()

    # Load videos from all teachers
    videos = db.execute('SELECT * FROM videos ORDER BY created_at DESC').fetchall()

    return render_template(
        "student_dashboard.html",
        user=user,
        doubts=doubts,
        videos=videos
    )


@app.route('/teacher/upload_video', methods=['GET', 'POST'])
def upload_video():
    user = current_user()
    if not user:
        flash('Login required')
        return redirect(url_for('login'))
    if user['role'] != 'teacher':
        flash('Unauthorized - teacher accounts only')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        video_url = request.form.get('video_url', '').strip()
        description = request.form.get('description', '').strip()
        if not title or not video_url:
            flash('Title and video URL required')
            return redirect(url_for('upload_video'))
        db = get_db()
        db.execute('INSERT INTO videos (teacher_id, title, video_url, description, created_at) VALUES (?, ?, ?, ?, ?)',
                   (user['id'], title, video_url, description, datetime.utcnow().isoformat()))
        db.commit()
        flash('Video saved')
        return redirect(url_for('teacher_dashboard'))
    return render_template('upload_video.html', user=user)

@app.route('/teacher/create_meeting', methods=['GET', 'POST'])
def create_meeting():
    user = current_user()
    if not user:
        flash('Login required')
        return redirect(url_for('login'))
    if user['role'] != 'teacher':
        flash('Unauthorized - teacher accounts only')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        link = request.form.get('link', '').strip()
        time = request.form.get('time', '').strip()  # store as ISO string or text
        topic = request.form.get('topic', '').strip()
        if not link or not time or not topic:
            flash('All fields required')
            return redirect(url_for('create_meeting'))
        db = get_db()
        db.execute('INSERT INTO meetings (teacher_id, link, time, topic, created_at) VALUES (?, ?, ?, ?, ?)',
                   (user['id'], link, time, topic, datetime.utcnow().isoformat()))
        db.commit()
        flash('Meeting scheduled')
        return redirect(url_for('teacher_dashboard'))
    return render_template('create_meeting.html', user=user)

@app.route('/meetings')
def view_meetings():
    # view all upcoming meetings (students can join)
    db = get_db()
    cur = db.execute('SELECT m.*, u.username as teacher_name FROM meetings m LEFT JOIN users u ON m.teacher_id = u.id ORDER BY m.time ASC')
    meetings = cur.fetchall()
    return render_template('view_meetings.html', user=current_user(), meetings=meetings)

# ----- Profile (unchanged) -----
@app.route('/user/<username>')
def profile(username):
    db = get_db()
    cur = db.execute('SELECT * FROM users WHERE username = ?', (username,))
    user_row = cur.fetchone()
    if not user_row:
        flash('User not found')
        return redirect(url_for('index'))
    cur = db.execute('SELECT * FROM doubts WHERE user_id = ? ORDER BY created_at DESC', (user_row['id'],))
    user_doubts = cur.fetchall()
    return render_template('profile.html', profile_user=user_row, doubts=user_doubts, user=current_user())



if __name__ == '__main__':
    app.run(debug=True)
