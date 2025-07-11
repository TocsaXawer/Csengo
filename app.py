import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, date, timedelta
from dateutil.relativedelta import relativedelta
import json
import calendar
import locale
from functools import wraps
import secrets

# --- App Configuration ---
app = Flask(__name__)

# Set locale for Hungarian month names
try:
    locale.setlocale(locale.LC_TIME, 'hu_HU.UTF-8')
except locale.Error:
    print("Figyelmeztetés: A 'hu_HU.UTF-8' területi beállítás nem található.")

app.config['SECRET_KEY'] = 'a-nagyon-titkos-kulcs-amit-soha-nem-talalsz-ki'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///school_schedule.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'mp3'}

# Ensure the upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'A tartalom megtekintéséhez jelentkezzen be.'
login_manager.login_message_category = 'info'

# --- Permissions ---
class Permission:
    VIEW = 1
    EDIT_SCHEDULE = 2
    MANAGE_USERS = 4
    VIEW_LOGS = 8
    ADMIN = 16

# --- Database Models ---

roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'))
)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', secondary=roles_users, back_populates='roles')

    def __init__(self, name, permissions):
        self.name = name
        self.permissions = permissions

    def has_permission(self, perm):
        return self.permissions & perm == perm

    @staticmethod
    def insert_roles():
        roles = {
            'Felhasználó': Permission.VIEW,
            'Szerkesztő': Permission.VIEW | Permission.EDIT_SCHEDULE,
            'Adminisztrátor': Permission.VIEW | Permission.EDIT_SCHEDULE | Permission.MANAGE_USERS | Permission.VIEW_LOGS | Permission.ADMIN
        }
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r, permissions=roles[r])
            role.permissions = roles[r]
            db.session.add(role)
        db.session.commit()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    roles = db.relationship('Role', secondary=roles_users, back_populates='users')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def can(self, perm):
        return any(role.has_permission(perm) for role in self.roles)

    def is_admin(self):
        return self.can(Permission.ADMIN)


class ScheduleType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    periods = db.Column(db.Text, nullable=False)
    start_bell_filename = db.Column(db.String(255), nullable=True)
    end_bell_filename = db.Column(db.String(255), nullable=True)
    signal_bell_filename = db.Column(db.String(255), nullable=True)

class CalendarEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(10), unique=True, nullable=False)
    schedule_type_id = db.Column(db.Integer, db.ForeignKey('schedule_type.id'), nullable=False)
    schedule_type = db.relationship('ScheduleType', backref=db.backref('events', lazy=True))
    description = db.Column(db.String(100))

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    details = db.Column(db.String(255), nullable=True)
    user = db.relationship('User', backref=db.backref('logs', lazy=True, cascade="all, delete-orphan"))

class ApiKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    key_type = db.Column(db.String(20), nullable=False, default='query')
    last_seen = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User')

class Setting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(255), nullable=True)

# --- Decorators ---
def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                flash('Nincs jogosultsága ehhez a művelethez.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    return permission_required(Permission.ADMIN)(f)

def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key_header = request.headers.get('X-API-Key')
        if not api_key_header:
            return jsonify({'message': 'Hiányzó API kulcs (X-API-Key header).'}), 401
        
        api_key = ApiKey.query.filter_by(key=api_key_header, key_type='query').first()
        if not api_key:
            return jsonify({'message': 'Érvénytelen vagy nem lekérdező típusú API kulcs.'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# --- Custom Jinja Filters & Processors ---
@app.context_processor
def inject_utilities():
    # Use UTC now for consistent time handling in templates, especially for comparisons.
    return dict(now=datetime.utcnow, Permission=Permission, timedelta=timedelta)

@app.template_filter('fromjson')
def from_json_filter(value):
    if not value: return []
    try: return json.loads(value)
    except (json.JSONDecodeError, TypeError): return []

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- Helper Functions ---
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def add_log(action, details=None):
    if current_user.is_authenticated:
        log_entry = Log(user_id=current_user.id, username=current_user.username, action=action, details=details)
        db.session.add(log_entry)

def get_todays_schedule():
    today_str = datetime.now().strftime('%Y-%m-%d')
    event = CalendarEvent.query.filter_by(date=today_str).first()
    if event:
        schedule_type = event.schedule_type
        description = event.description
    else:
        schedule_type = ScheduleType.query.filter_by(name='Normál').first()
        description = "Normál tanítási nap"
    if not schedule_type:
        return "Nincs adat", "Nincs alapértelmezett csengetési rend.", [], None, None, None
    
    try:
        periods = json.loads(schedule_type.periods)
    except (json.JSONDecodeError, TypeError):
        periods = []
    
    return (schedule_type.name, description, periods, 
            schedule_type.start_bell_filename, 
            schedule_type.end_bell_filename, 
            schedule_type.signal_bell_filename)

### ÚJ ###
# Dekorátor a P2P eszközök API kulcsának ellenőrzésére
def p2p_api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key_header = request.headers.get('X-API-Key')
        if not api_key_header:
            return jsonify({'message': 'Hiányzó API kulcs (X-API-Key header).'}), 401
        
        api_key = ApiKey.query.filter_by(key=api_key_header, key_type='p2p').first()
        if not api_key:
            return jsonify({'message': 'Érvénytelen vagy nem P2P típusú API kulcs.'}), 403
        
        # A dekorátor átadja az api_key objektumot a route-nak
        return f(api_key=api_key, *args, **kwargs)
    return decorated_function

# Függvény, amely megkeresi a legközelebbi csengetési időpontot a jövőben.
def get_next_ringing_info():
    now = datetime.now()
    # Keressük a következő csengetést max 1 évig előre.
    for day_offset in range(366):
        target_day = now.date() + timedelta(days=day_offset)
        target_day_str = target_day.strftime('%Y-%m-%d')

        # Csengetési rend meghatározása az adott napra
        event = CalendarEvent.query.filter_by(date=target_day_str).first()
        if event:
            schedule_type = event.schedule_type
        else:
            if target_day.weekday() >= 5: # Hétvége
                schedule_type = ScheduleType.query.filter_by(name='Nincs csengetés').first()
            else: # Hétköznap
                schedule_type = ScheduleType.query.filter_by(name='Normál').first()

        if not schedule_type or not schedule_type.periods:
            continue

        try:
            periods = json.loads(schedule_type.periods)
            if not periods: continue
        except (json.JSONDecodeError, TypeError):
            continue

        # Események (időpont + típus) összegyűjtése az adott napra
        events_for_day = []
        for period in periods:
            if period.get('start'):
                events_for_day.append({'time_str': period['start'], 'type': 'start'})
            if period.get('end'):
                events_for_day.append({'time_str': period['end'], 'type': 'end'})
        
        future_ringings_on_day = []
        for event_data in events_for_day:
            try:
                hour, minute = map(int, event_data['time_str'].split(':'))
                ringing_datetime = datetime.combine(target_day, datetime.min.time()).replace(hour=hour, minute=minute)
                
                if ringing_datetime > now:
                    future_ringings_on_day.append({
                        'time': ringing_datetime,
                        'type': event_data['type']
                    })
            except (ValueError, TypeError):
                continue

        # Ha találtunk jövőbeli eseményt, a legkorábbit visszaadjuk
        if future_ringings_on_day:
            # Rendezés idő szerint, hogy biztosan a legközelebbi legyen az első
            future_ringings_on_day.sort(key=lambda x: x['time'])
            next_event = future_ringings_on_day[0]
            
            return {
                "next_ringing_time_utc": next_event['time'].isoformat(),
                "ring_type": next_event['type'], # 'start' vagy 'end'
                "schedule_name": schedule_type.name,
                "start_bell_filename": schedule_type.start_bell_filename,
                "end_bell_filename": schedule_type.end_bell_filename,
                "signal_bell_filename": schedule_type.signal_bell_filename,
            }
    
    # Ha a ciklus lefutott és nem találtunk semmit
    return None

### ÚJ ###
@app.route('/api/p2p/next-ringing')
@p2p_api_key_required
def p2p_next_ringing(api_key):
    """
    P2P API végpont, amely visszaadja a legközelebbi csengetés időpontját
    és a hozzá tartozó KICCSENGŐ vagy BECSENGŐ hangfájlt, valamint a jelzőcsengőt.
    """
    api_key.last_seen = datetime.utcnow()
    
    ringing_info = get_next_ringing_info()
    
    db.session.commit()

    if not ringing_info:
        return jsonify({'message': 'Nincs következő csengetés beütemezve.'}), 404

    # A választípus ('start' vagy 'end') alapján kiválasztjuk a megfelelő hangfájlt
    main_bell_filename = None
    if ringing_info['ring_type'] == 'start':
        main_bell_filename = ringing_info.get('start_bell_filename')
    elif ringing_info['ring_type'] == 'end':
        main_bell_filename = ringing_info.get('end_bell_filename')

    # A válasz összeállítása
    response_data = {
        'next_ringing_time_utc': ringing_info['next_ringing_time_utc'],
        'ring_type': ringing_info['ring_type'],
        'schedule_name': ringing_info['schedule_name'],
        'main_bell_url': url_for('serve_upload', filename=main_bell_filename, _external=True) if main_bell_filename else None,
        'signal_bell_url': url_for('serve_upload', filename=ringing_info.get('signal_bell_filename'), _external=True) if ringing_info.get('signal_bell_filename') else None
    }
    
    return jsonify(response_data)

    
# --- Frontend Routes ---
@app.route('/')
def index():
    schedule_name, description, periods, start_bell, end_bell, signal_bell = get_todays_schedule()
    return render_template('index.html', schedule_name=schedule_name, description=description, periods=periods, start_bell_url=url_for('serve_upload', filename=start_bell) if start_bell else None, end_bell_url=url_for('serve_upload', filename=end_bell) if end_bell else None, signal_bell_url=url_for('serve_upload', filename=signal_bell) if signal_bell else None)

@app.route('/get_current_time')
def get_current_time():
    return jsonify({'time': datetime.now().strftime('%H:%M:%S')})

@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- API Endpoints ---
@app.route('/api/esp32/data')
@api_key_required
def esp32_data():
    schedule_name, description, _, start_bell, end_bell, signal_bell = get_todays_schedule()
    current_time = datetime.now().strftime('%H:%M:%S')
    response_data = {
        'time': current_time, 
        'schedule_mode': schedule_name or "N/A", 
        'description': description or "N/A",
        'start_bell_url': url_for('serve_upload', filename=start_bell, _external=True) if start_bell else None,
        'end_bell_url': url_for('serve_upload', filename=end_bell, _external=True) if end_bell else None,
        'signal_bell_url': url_for('serve_upload', filename=signal_bell, _external=True) if signal_bell else None
    }
    return jsonify(response_data)


@app.route('/api/p2p/heartbeat', methods=['POST'])
def p2p_heartbeat():
    api_key_header = request.headers.get('X-API-Key')
    if not api_key_header:
        return jsonify({'status': 'error', 'message': 'Hiányzó API kulcs.'}), 401
    
    api_key = ApiKey.query.filter_by(key=api_key_header, key_type='p2p').first()
    if not api_key:
        return jsonify({'status': 'error', 'message': 'Érvénytelen vagy nem P2P típusú kulcs.'}), 403
    
    api_key.last_seen = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'status': 'success', 'message': f'Heartbeat fogadva: {api_key.name}'})

@app.route('/api/get-sounds')
@login_required # Only authenticated users can get sound info for the web player
def get_sounds():
    main_bell = Setting.query.filter_by(key='main_bell_filename').first()
    signal_bell = Setting.query.filter_by(key='signal_bell_filename').first()
    return jsonify({
        'main_bell_url': url_for('serve_upload', filename=main_bell.value) if main_bell and main_bell.value else None,
        'signal_bell_url': url_for('serve_upload', filename=signal_bell.value) if signal_bell and signal_bell.value else None
    })

# --- Admin and Login Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            add_log("Sikeres bejelentkezés")
            db.session.commit()
            flash('Sikeres bejelentkezés!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Hibás felhasználónév vagy jelszó.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    add_log("Kijelentkezés")
    db.session.commit()
    logout_user()
    flash('Sikeres kijelentkezés.', 'info')
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.can(Permission.EDIT_SCHEDULE): return redirect(url_for('admin_schedules'))
    if current_user.can(Permission.MANAGE_USERS): return redirect(url_for('admin_users'))
    if current_user.can(Permission.VIEW_LOGS): return redirect(url_for('admin_logs'))
    flash('Nincs adminisztrátori jogosultsága az oldalak megtekintéséhez.', 'info')
    return redirect(url_for('index'))

# @app.route('/admin/sounds', methods=['GET', 'POST'])
# @login_required
# @permission_required(Permission.EDIT_SCHEDULE)
# def admin_sounds():
#     if request.method == 'POST':
#         for key, file_storage in [('main_bell', request.files.get('main_bell_file')), ('signal_bell', request.files.get('signal_bell_file'))]:
#             if file_storage and file_storage.filename != '':
#                 if allowed_file(file_storage.filename):
#                     filename = secure_filename(file_storage.filename)
#                     file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#                     file_storage.save(file_path)
                    
#                     setting_key = f'{key}_filename'
#                     setting = Setting.query.filter_by(key=setting_key).first()
#                     if not setting:
#                         setting = Setting(key=setting_key)
#                         db.session.add(setting)
#                     setting.value = filename
                    
#                     add_log(f"Hangfájl feltöltve: {key}", f"Fájlnév: {filename}")
#                     flash(f'"{filename}" sikeresen feltöltve.', 'success')
#                 else:
#                     flash('Érvénytelen fájltípus. Csak MP3 fájlok engedélyezettek.', 'danger')
#         db.session.commit()
#         return redirect(url_for('admin_sounds'))
        
#     main_bell = Setting.query.filter_by(key='main_bell_filename').first()
#     signal_bell = Setting.query.filter_by(key='signal_bell_filename').first()
#     return render_template('admin_sounds.html', main_bell=main_bell, signal_bell=signal_bell)

@app.route('/admin/schedules', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.EDIT_SCHEDULE)
def admin_schedules():
    if request.method == 'POST':
        schedule_name = request.form.get('name')
        if not schedule_name:
            flash('A csengetési rend neve kötelező.', 'danger')
        else:
            new_schedule_type = ScheduleType(name=schedule_name, periods=json.dumps([]))
            db.session.add(new_schedule_type)
            add_log("Új csengetési rend létrehozva", f"Név: {schedule_name}")
            db.session.commit()
            flash(f'"{schedule_name}" csengetési rend létrehozva.', 'success')
        return redirect(url_for('admin_schedules'))
    schedule_types = ScheduleType.query.all()
    return render_template('admin_schedules.html', schedule_types=schedule_types)


@app.route('/admin/schedules/edit/<int:schedule_id>', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.EDIT_SCHEDULE)
def edit_schedule(schedule_id):
    schedule_type = db.session.get(ScheduleType, schedule_id)
    if not schedule_type:
        flash('A megadott csengetési rend nem található.', 'danger')
        return redirect(url_for('admin_schedules'))
    if request.method == 'POST':
        # Update periods
        periods_data = []
        period_names = request.form.getlist('period_name[]')
        start_times = request.form.getlist('start_time[]')
        end_times = request.form.getlist('end_time[]')
        for i in range(len(period_names)):
            if period_names[i] and start_times[i] and end_times[i]:
                periods_data.append({'name': period_names[i], 'start': start_times[i], 'end': end_times[i]})
        schedule_type.periods = json.dumps(periods_data)
        
        # Handle file uploads
        file_uploads = {
            'start_bell': request.files.get('start_bell_file'),
            'end_bell': request.files.get('end_bell_file'),
            'signal_bell': request.files.get('signal_bell_file')
        }
        for key, file_storage in file_uploads.items():
            if file_storage and file_storage.filename != '':
                if allowed_file(file_storage.filename):
                    filename = secure_filename(file_storage.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file_storage.save(file_path)
                    setattr(schedule_type, f'{key}_filename', filename)
                    add_log(f"Hangfájl frissítve: {schedule_type.name}", f"Fájl: {filename}")
                    flash(f'"{filename}" sikeresen feltöltve.', 'success')
                else:
                    flash('Érvénytelen fájltípus. Csak MP3 fájlok engedélyezettek.', 'danger')

        add_log("Csengetési rend módosítva", f"Név: {schedule_type.name}")
        db.session.commit()
        flash(f'"{schedule_type.name}" csengetési rend frissítve.', 'success')
        return redirect(url_for('edit_schedule', schedule_id=schedule_id))
        
    periods = json.loads(schedule_type.periods or '[]')
    return render_template('edit_schedule.html', schedule_type=schedule_type, periods=periods)

@app.route('/admin/schedules/delete/<int:schedule_id>', methods=['POST'])
@login_required
@permission_required(Permission.EDIT_SCHEDULE)
def delete_schedule(schedule_id):
    schedule_type = db.session.get(ScheduleType, schedule_id)
    if schedule_type:
        if schedule_type.name in ['Normál', 'Nincs csengetés']:
            flash(f'A "{schedule_type.name}" csengetési rend nem törölhető, mert alapértelmezett.', 'warning')
            return redirect(url_for('admin_schedules'))
        if CalendarEvent.query.filter_by(schedule_type_id=schedule_id).first():
            flash('Ez a csengetési rend nem törölhető, mert hozzá van rendelve egy vagy több naptári naphoz.', 'danger')
            return redirect(url_for('admin_schedules'))
        schedule_name = schedule_type.name
        db.session.delete(schedule_type)
        add_log("Csengetési rend törölve", f"Név: {schedule_name}")
        db.session.commit()
        flash(f'"{schedule_name}" csengetési rend törölve.', 'success')
    else:
        flash('A törölni kívánt csengetési rend nem található.', 'danger')
    return redirect(url_for('admin_schedules'))

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.MANAGE_USERS)
def admin_users():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role_ids = request.form.getlist('roles', type=int)
        if not username or not password:
            flash('A felhasználónév és a jelszó megadása kötelező.', 'danger')
        elif User.query.filter_by(username=username).first():
            flash('Ez a felhasználónév már foglalt.', 'warning')
        else:
            new_user = User(username=username)
            new_user.set_password(password)
            roles = Role.query.filter(Role.id.in_(role_ids)).all()
            new_user.roles = roles
            db.session.add(new_user)
            add_log("Új felhasználó létrehozva", f"Felhasználónév: {username}")
            db.session.commit()
            flash(f'"{username}" nevű felhasználó sikeresen létrehozva.', 'success')
        return redirect(url_for('admin_users'))
    users = User.query.all()
    roles = Role.query.all()
    return render_template('admin_users.html', users=users, roles=roles)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.MANAGE_USERS)
def edit_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash('A felhasználó nem található.', 'danger')
        return redirect(url_for('admin_users'))
    if request.method == 'POST':
        role_ids = request.form.getlist('roles', type=int)
        user.roles = Role.query.filter(Role.id.in_(role_ids)).all()
        add_log("Felhasználó szerepkörei módosítva", f"Felhasználó: {user.username}")
        db.session.commit()
        flash(f'"{user.username}" szerepkörei frissítve.', 'success')
        return redirect(url_for('admin_users'))
    roles = Role.query.all()
    return render_template('edit_user.html', user=user, roles=roles)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@permission_required(Permission.MANAGE_USERS)
def delete_user(user_id):
    if user_id == current_user.id:
        flash('Saját magát nem törölheti.', 'danger')
        return redirect(url_for('admin_users'))
    user_to_delete = db.session.get(User, user_id)
    if user_to_delete:
        username = user_to_delete.username
        db.session.delete(user_to_delete)
        add_log("Felhasználó törölve", f"Felhasználónév: {username}")
        db.session.commit()
        flash(f'"{username}" nevű felhasználó törölve.', 'success')
    else:
        flash('A törölni kívánt felhasználó nem található.', 'warning')
    return redirect(url_for('admin_users'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if not current_user.check_password(old_password):
            flash('A jelenlegi jelszó hibás.', 'danger')
        elif not new_password:
            flash('Az új jelszó nem lehet üres.', 'danger')
        elif new_password != confirm_password:
            flash('Az új jelszavak nem egyeznek.', 'danger')
        else:
            current_user.set_password(new_password)
            add_log("Jelszó megváltoztatva")
            db.session.commit()
            flash('Jelszó sikeresen megváltoztatva!', 'success')
            return redirect(url_for('change_password'))
    return render_template('change_password.html')

@app.route('/admin/logs')
@login_required
@permission_required(Permission.VIEW_LOGS)
def admin_logs():
    page = request.args.get('page', 1, type=int)
    logs = Log.query.order_by(Log.timestamp.desc()).paginate(page=page, per_page=20)
    return render_template('admin_logs.html', logs=logs)

@app.route('/admin/api-keys', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_api_keys():
    if request.method == 'POST':
        name = request.form.get('name')
        key_type = request.form.get('key_type', 'query')
        if not name:
            flash('Az API kulcs nevének megadása kötelező.', 'danger')
        else:
            new_key_str = secrets.token_urlsafe(32)
            new_api_key = ApiKey(name=name, key=new_key_str, user_id=current_user.id, key_type=key_type)
            db.session.add(new_api_key)
            add_log("API kulcs létrehozva", f"Név: {name}, Típus: {key_type}")
            db.session.commit()
            flash(f'Új API kulcs "{name}" néven létrehozva. Másolja ki most, mert később nem lesz látható!', 'success')
            api_keys = ApiKey.query.order_by(ApiKey.created_at.desc()).all()
            return render_template('admin_api_keys.html', api_keys=api_keys, new_key=new_key_str, new_key_name=name)
    
    api_keys = ApiKey.query.order_by(ApiKey.created_at.desc()).all()
    return render_template('admin_api_keys.html', api_keys=api_keys)

@app.route('/admin/api-keys/delete/<int:key_id>', methods=['POST'])
@login_required
@admin_required
def delete_api_key(key_id):
    key_to_delete = db.session.get(ApiKey, key_id)
    if key_to_delete:
        key_name = key_to_delete.name
        db.session.delete(key_to_delete)
        add_log("API kulcs törölve", f"Név: {key_name}")
        db.session.commit()
        flash(f'"{key_name}" nevű API kulcs sikeresen törölve.', 'success')
    else:
        flash('A törölni kívánt API kulcs nem található.', 'warning')
    return redirect(url_for('admin_api_keys'))

@app.route('/api/p2p-devices')
@login_required
@admin_required
def api_p2p_devices():
    """API végpont, amely visszaadja az összes P2P eszköz állapotát."""
    devices = ApiKey.query.filter_by(key_type='p2p').order_by(ApiKey.name).all()
    device_list = []
    # Az 5 percnél nem régebbi életjellel rendelkező eszköz számít online-nak
    five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
    for device in devices:
        is_online = device.last_seen and device.last_seen > five_minutes_ago
        device_list.append({
            'name': device.name,
            'status': 'Online' if is_online else 'Offline',
            'last_seen': device.last_seen.strftime('%Y-%m-%d %H:%M:%S') if device.last_seen else 'Soha'
        })
    return jsonify(device_list)

@app.route('/admin/p2p-status')
@login_required
@admin_required
def admin_p2p_status():
    # Az eszközlista mostantól dinamikusan, JavaScript-tel töltődik be.
    # A Python-nak itt már nem kell átadnia az eszközök listáját.
    return render_template('admin_p2p_status.html')

@app.route('/admin/calendar')
@app.route('/admin/calendar/<int:year>/<int:month>')
@login_required
@permission_required(Permission.EDIT_SCHEDULE)
def admin_calendar(year=None, month=None):
    today = date.today()
    if year is None or month is None:
        year, month = today.year, today.month
    try:
        current_date = date(year, month, 1)
    except (ValueError, TypeError):
        return redirect(url_for('admin_calendar'))
    cal = calendar.Calendar(firstweekday=0) 
    calendar_weeks = cal.monthdatescalendar(year, month)
    first_day_in_grid = calendar_weeks[0][0]
    last_day_in_grid = calendar_weeks[-1][-1]
    events_query = CalendarEvent.query.filter(
        CalendarEvent.date >= first_day_in_grid.strftime('%Y-%m-%d'),
        CalendarEvent.date <= last_day_in_grid.strftime('%Y-%m-%d')
    ).all()
    events_dict = {event.date: event for event in events_query}
    prev_month_date = current_date - relativedelta(months=1)
    next_month_date = current_date + relativedelta(months=1)
    month_name = current_date.strftime('%B').capitalize()
    schedule_types = ScheduleType.query.all()
    return render_template(
        'admin_calendar.html', 
        schedule_types=schedule_types, year=year, month=month,
        month_name=month_name, calendar_weeks=calendar_weeks,
        events=events_dict, today=today, prev_month=prev_month_date,
        next_month=next_month_date
    )

@app.route('/api/calendar_events', methods=['POST'])
@login_required
@permission_required(Permission.EDIT_SCHEDULE)
def set_calendar_event():
    data = request.get_json()
    date_str = data.get('date')
    schedule_type_id = data.get('schedule_type_id')
    description = data.get('description', '')
    if not date_str or not schedule_type_id:
        return jsonify({'status': 'error', 'message': 'Hiányzó adatok. Kérjük, válasszon csengetési rendet.'}), 400
    event = CalendarEvent.query.filter_by(date=date_str).first()
    if event:
        event.schedule_type_id = schedule_type_id
        event.description = description
    else:
        event = CalendarEvent(date=date_str, schedule_type_id=schedule_type_id, description=description)
        db.session.add(event)
    add_log("Naptári esemény módosítva/létrehozva", f"Dátum: {date_str}, Leírás: {description}")
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'Naptár frissítve.'})

@app.route('/api/calendar_events/delete', methods=['POST'])
@login_required
@permission_required(Permission.EDIT_SCHEDULE)
def delete_calendar_event():
    data = request.get_json()
    date_str = data.get('date')
    if not date_str:
        return jsonify({'status': 'error', 'message': 'Hiányzó dátum.'}), 400
    event = CalendarEvent.query.filter_by(date=date_str).first()
    if event:
        db.session.delete(event)
        add_log("Naptári esemény törölve", f"Dátum: {date_str}")
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Esemény törölve.'})
    else:
        return jsonify({'status': 'error', 'message': 'Nincs esemény ezen a napon.'}), 404

# --- One-time Setup Command ---
@app.cli.command('init-db')
def init_db_command():
    db.drop_all()
    db.create_all()
    print("Adatbázis táblák újragenerálva.")
    
    Role.insert_roles()
    print("Szerepkörök beillesztve/frissítve.")

    if not User.query.filter_by(username='admin').first():
        print("Alapértelmezett admin felhasználó létrehozása...")
        admin_user = User(username='admin')
        admin_user.set_password('admin123')
        admin_role = Role.query.filter_by(name='Adminisztrátor').first()
        admin_user.roles.append(admin_role)
        db.session.add(admin_user)
    else:
        print("Az admin felhasználó már létezik.")
    
    if not ScheduleType.query.filter_by(name='Normál').first():
        print("'Normál' csengetési rend létrehozása...")
        normal_periods = json.dumps([
            {'name': '1. óra', 'start': '08:00', 'end': '08:45'}, {'name': '2. óra', 'start': '08:55', 'end': '09:40'},
            {'name': '3. óra', 'start': '09:50', 'end': '10:35'}, {'name': '4. óra', 'start': '10:55', 'end': '11:40'},
            {'name': '5. óra', 'start': '11:50', 'end': '12:35'}, {'name': '6. óra', 'start': '12:45', 'end': '13:30'},
        ])
        db.session.add(ScheduleType(name='Normál', periods=normal_periods))
    
    if not ScheduleType.query.filter_by(name='Rövidített').first():
        print("'Rövidített' csengetési rend létrehozása...")
        short_periods = json.dumps([
            {'name': '1. óra', 'start': '08:00', 'end': '08:35'}, {'name': '2. óra', 'start': '08:45', 'end': '09:20'},
            {'name': '3. óra', 'start': '09:30', 'end': '10:05'},
        ])
        db.session.add(ScheduleType(name='Rövidített', periods=short_periods))

    if not ScheduleType.query.filter_by(name='Nincs csengetés').first():
        print("'Nincs csengetés' csengetési rend létrehozása...")
        db.session.add(ScheduleType(name='Nincs csengetés', periods=json.dumps([])))
    
    db.session.commit()
    print("Adatbázis sikeresen inicializálva.")
    print("Admin adatok: username='admin', password='admin123'")


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000, host='0.0.0.0')
