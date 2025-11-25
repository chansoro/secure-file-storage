import os
import datetime
import uuid
from flask import Flask, request, jsonify, send_file, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import jwt
from functools import wraps

# Configuration
app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = 'your_secret_key_here_change_me' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB Max limit

# Enable CORS to allow frontend development on different ports if needed
CORS(app)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize Database
db = SQLAlchemy(app)

# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class FileRecord(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(255), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    encrypted = db.Column(db.Boolean, default=False)
    iv = db.Column(db.String(100), nullable=True)   # Base64 IV
    salt = db.Column(db.String(100), nullable=True) # Base64 Salt

# --- Helper Functions ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
        except Exception as e:
            return jsonify({'message': 'Token is invalid!'}), 401
            
        return f(current_user, *args, **kwargs)
    return decorated

# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html') 

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing username or password'}), 400
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'User already exists'}), 409
    
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'Registered successfully'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing credentials'}), 400
        
    user = User.query.filter_by(username=data['username']).first()
    
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401
        
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    return jsonify({'token': token})

@app.route('/api/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    if 'file' not in request.files:
        return jsonify({'message': 'No file part'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400

    # Get metadata from form
    custom_filename = request.form.get('filename') or file.filename
    is_encrypted = request.form.get('encrypted') == 'true'
    iv = request.form.get('iv')
    salt = request.form.get('salt')

    # Secure the filename for storage on disk
    safe_filename = secure_filename(f"{uuid.uuid4().hex}_{custom_filename}")
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
    
    # Save file
    file.save(save_path)
    file_size = os.path.getsize(save_path)
    
    # Create DB Record
    new_file = FileRecord(
        user_id=current_user.id,
        filename=custom_filename,
        filepath=safe_filename,  
        size=file_size,
        encrypted=is_encrypted,
        iv=iv,
        salt=salt
    )
    db.session.add(new_file)
    db.session.commit()
    
    return jsonify({'message': 'File uploaded successfully', 'id': new_file.id}), 201

@app.route('/api/files', methods=['GET'])
@token_required
def list_files(current_user):
    files = FileRecord.query.filter_by(user_id=current_user.id).order_by(FileRecord.uploaded_at.desc()).all()
    output = []
    for f in files:
        output.append({
            'id': f.id,
            'filename': f.filename,
            'size': f.size,
            'uploaded_at': f.uploaded_at.isoformat(),
            'encrypted': f.encrypted,
            # We send IV/Salt so the client can decrypt without asking user for them (if they trust server storage)
            'iv': f.iv,
            'salt': f.salt 
        })
    return jsonify(output)

@app.route('/api/download/<file_id>', methods=['GET'])
@token_required
def download_file(current_user, file_id):
    file_record = FileRecord.query.filter_by(id=file_id, user_id=current_user.id).first()
    if not file_record:
        return jsonify({'message': 'File not found'}), 404
        
    path = os.path.join(app.config['UPLOAD_FOLDER'], file_record.filepath)
    if not os.path.exists(path):
        return jsonify({'message': 'File missing from disk'}), 404
        
    return send_file(path, as_attachment=True, download_name=file_record.filename)

@app.route('/api/files/<file_id>', methods=['DELETE'])
@token_required
def delete_file(current_user, file_id):
    file_record = FileRecord.query.filter_by(id=file_id, user_id=current_user.id).first()
    if not file_record:
        return jsonify({'message': 'File not found'}), 404
        
    # Remove from disk
    path = os.path.join(app.config['UPLOAD_FOLDER'], file_record.filepath)
    if os.path.exists(path):
        os.remove(path)
        
    # Remove from DB
    db.session.delete(file_record)
    db.session.commit()
    
    return jsonify({'message': 'File deleted'})

# Initialize DB on startup (for development simplicity)
with app.app_context():
    db.create_all()

if __name__ == '__main__':

    app.run(debug=True, port=5000)
