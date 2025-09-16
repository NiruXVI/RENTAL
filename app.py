from flask import Flask, render_template, redirect, url_for, request, session, flash, send_from_directory, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, join_room, leave_room, emit
from sqlalchemy import or_, and_
from functools import wraps
from random import randint
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from werkzeug.utils import secure_filename
from dbfread import DBF



# --- Flask-Mail for email notifications ---
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rentease.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Flask-Mail Config ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'nikuronishina@gmail.com'  # Replace with your Gmail
app.config['MAIL_PASSWORD'] = 'wxsa jxmv fqav yetc'  # Use an App Password
mail = Mail(app)


UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads')
PROFILE_PICS_FOLDER = os.path.join(UPLOAD_FOLDER, 'profile_pics')
USER_DOCS_FOLDER = os.path.join(UPLOAD_FOLDER, 'user_docs')
PROPERTY_DOCS_FOLDER = os.path.join(UPLOAD_FOLDER, 'property_docs')
PROPERTY_IMAGES_FOLDER = os.path.join(UPLOAD_FOLDER, 'property_images')
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'pdf'}

for folder in [UPLOAD_FOLDER, PROFILE_PICS_FOLDER, USER_DOCS_FOLDER, PROPERTY_DOCS_FOLDER, PROPERTY_IMAGES_FOLDER]:
    os.makedirs(folder, exist_ok=True)

app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
db = SQLAlchemy(app)
socketio = SocketIO(app)

# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Models ---
class User(UserMixin, db.Model):
    __tablename__ = 'tbl_users'
    id = db.Column('User_Id', db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    contact = db.Column(db.String(255))
    role = db.Column(db.String(50), nullable=False)
    verified = db.Column(db.Boolean, default=False)
    verification_requested = db.Column(db.Boolean, default=False)
    profile_pic = db.Column(db.String(255))
    otp_code = db.Column(db.String(10))  # <-- Add this
    otp_expiry = db.Column(db.DateTime)  # <-- And this
    properties = db.relationship('Property', backref='owner', lazy=True)
    user_docs = db.relationship('UserDocument', backref='user', cascade="all, delete-orphan")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class UserDocument(db.Model):
    __tablename__ = 'tbl_user_documents'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('tbl_users.User_Id'), nullable=False)
    doc_type = db.Column(db.String(50))
    file_path = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

class Property(db.Model):
    __tablename__ = 'tbl_property'
    id = db.Column('property_id', db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('tbl_users.User_Id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255))
    address = db.Column(db.String(255))
    price = db.Column(db.String(255))
    type = db.Column(db.String(50))
    status = db.Column(db.String(50))
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    verified = db.Column(db.Boolean, default=False)
    location = db.relationship('Location', uselist=False, backref='property')
    images = db.relationship('Image', backref='property', lazy=True)
    property_docs = db.relationship('PropertyDocument', backref='property', lazy=True)
    rental_requests = db.relationship('RentalRequest', backref='property', lazy=True)

class PropertyDocument(db.Model):
    __tablename__ = 'tbl_property_documents'
    id = db.Column(db.Integer, primary_key=True)
    property_id = db.Column(db.Integer, db.ForeignKey('tbl_property.property_id'), nullable=False)
    doc_type = db.Column(db.String(50))
    file_path = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

class Location(db.Model):
    __tablename__ = 'tbl_location'
    id = db.Column('location_id', db.Integer, primary_key=True)
    property_id = db.Column(db.Integer, db.ForeignKey('tbl_property.property_id'), nullable=False)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    city = db.Column(db.String(255))
    province = db.Column(db.String(255))

class Image(db.Model):
    __tablename__ = 'tbl_image'
    id = db.Column('image_id', db.Integer, primary_key=True)
    property_id = db.Column(db.Integer, db.ForeignKey('tbl_property.property_id'), nullable=False)
    image_file = db.Column(db.String(255), nullable=False)

class RentalRequest(db.Model):
    __tablename__ = 'tbl_rental_request'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('tbl_users.User_Id'), nullable=False)
    property_id = db.Column(db.Integer, db.ForeignKey('tbl_property.property_id'), nullable=False)
    status = db.Column(db.String(50), default='Pending')
    date = db.Column(db.DateTime, default=datetime.utcnow)

class AdminAction(db.Model):
    __tablename__ = 'tbl_adminaction'
    id = db.Column('action_id', db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('tbl_users.User_Id'), nullable=False)
    property_id = db.Column(db.Integer, db.ForeignKey('tbl_property.property_id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('tbl_users.User_Id'), nullable=True)
    action = db.Column(db.String(50))
    target_name = db.Column(db.String(255))
    date = db.Column(db.DateTime, default=datetime.utcnow)

class Review(db.Model):
    __tablename__ = 'tbl_review'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('tbl_users.User_Id'), nullable=False)
    property_id = db.Column(db.Integer, db.ForeignKey('tbl_property.property_id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.String(500))
    date = db.Column(db.DateTime, default=datetime.utcnow)

class UserMessage(db.Model):
    __tablename__ = 'tbl_message'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('tbl_users.User_Id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('tbl_users.User_Id'), nullable=False)
    content = db.Column(db.String(1000), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    attachment_url = db.Column(db.String(255))

class PropertyReview(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    property_id = db.Column(db.Integer, db.ForeignKey('tbl_property.property_id'))
    user_id = db.Column(db.Integer, db.ForeignKey('tbl_users.User_Id'))
    content = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='property_reviews')
    property = db.relationship('Property', backref='reviews')

# --- Utility Functions ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS

def send_verification_email(user, subject, body):
    try:
        msg = Message(subject, recipients=[user.email], body=body, sender=app.config['MAIL_USERNAME'])
        mail.send(msg)
    except Exception as e:
        print(f"Failed to send email: {e}")

@app.after_request
def after_request(response):
    if 'user_id' in session:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response


# --- Routes ---
@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    user = User.query.get(current_user.id)
    # Allow all users to access profile pictures
    if filename.startswith('profile_pics/'):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    # Allow all users to access chat attachments and profile pics
    if filename.startswith('chat_attachments/') or filename.startswith('profile_pics/'):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    # Property images and docs: only owner or admin
    if filename.startswith('property_images/') or filename.startswith('property_docs/'):
        prop = None
        if filename.startswith('property_images/'):
            image = Image.query.filter_by(image_file=filename).first()
            if image:
                prop = Property.query.get(image.property_id)
        elif filename.startswith('property_docs/'):
            doc = PropertyDocument.query.filter_by(file_path=filename).first()
            if doc:
                prop = Property.query.get(doc.property_id)
        if prop and (user.role == 'admin' or prop.user_id == user.id):
            return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
        else:
            abort(403)
    # User docs: only owner or admin
    if filename.startswith('user_docs/'):
        if user.role == 'admin':
            return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
        doc = UserDocument.query.filter_by(file_path=filename).first()
        if doc and doc.user_id == user.id:
            return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
        abort(403)
    abort(403)

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_user.role == 'landlord':
            return redirect(url_for('landlord_dashboard'))
        else:
            return redirect(url_for('listings'))
    return render_template('pages/landing.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_user.role == 'landlord':
            return redirect(url_for('landlord_dashboard'))
        else:
            return redirect(url_for('listings'))
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if not user:
            error = 'Email does not exist. Please register first.'
        elif not check_password_hash(user.password, password):
            error = 'Invalid password.'
        else:
            login_user(user)
            session['role'] = user.role
            session.permanent = True
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'landlord':
                return redirect(url_for('landlord_dashboard'))
            else:
                return redirect(url_for('listings'))
        flash(error, 'danger')
    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    response = app.make_response(redirect(url_for('index')))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    flash('You have been logged out successfully.', 'info')
    return response

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_user.role == 'landlord':
            return redirect(url_for('landlord_dashboard'))
        else:
            return redirect(url_for('listings'))
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        user_type = request.form.get('user_type', 'tenant')
        contact = request.form.get('contact')
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered.', 'danger')
            return render_template('auth/register.html')
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('auth/register.html')
        if user_type not in ['tenant', 'landlord']:
            flash('Invalid user type.', 'danger')
            return render_template('auth/register.html')
        hashed_password = generate_password_hash(password)
        otp = str(randint(100000, 999999))
        otp_expiry = datetime.utcnow() + timedelta(minutes=10)
        new_user = User(
            name=name,
            email=email,
            password=hashed_password,
            contact=contact,
            role=user_type,
            verified=False,
            otp_code=otp,
            otp_expiry=otp_expiry
        )
        db.session.add(new_user)
        db.session.commit()
        # Send OTP email
        send_verification_email(
            new_user,
            "Your RentEase OTP Code",
            f"Hello {name},\n\nYour OTP code is: {otp}\nIt will expire in 10 minutes.\n\nThank you!"
        )
        flash('Registration successful! Please check your email for the OTP code.', 'info')
        return redirect(url_for('verify_otp', email=email))
    return render_template('auth/register.html')



@app.route('/verify_otp/<email>', methods=['GET', 'POST'])
def verify_otp(email):
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('register'))
    if request.method == 'POST':
        otp_input = request.form.get('otp')
        if user.otp_code == otp_input and user.otp_expiry and datetime.utcnow() < user.otp_expiry:
            # Do not set user.verified = True here to avoid automatic verification
            user.otp_code = None
            user.otp_expiry = None
            db.session.commit()
            flash('Registration complete! Please upload your documents and request verification to access all features.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid or expired OTP code.', 'danger')
    return render_template('auth/verify_otp.html', email=email)


@app.route('/listings')
@login_required
def listings():
    user = User.query.get(current_user.id)
    if not user.verified:
        flash('You must be verified to browse listings.', 'warning')
        return redirect(url_for('profile'))
    filters = []
    city = request.args.get('city')
    province = request.args.get('province')
    type_ = request.args.get('type')
    min_price = request.args.get('min_price')
    max_price = request.args.get('max_price')
    if city:
        filters.append(Location.city == city)
    if province:
        filters.append(Location.province == province)
    if type_:
        filters.append(Property.type == type_)
    if min_price:
        filters.append(Property.price >= min_price)
    if max_price:
        filters.append(Property.price <= max_price)
    query = Property.query.filter_by(verified=True)
    if filters:
        query = query.join(Location).filter(*filters)
    listings = query.all()
    return render_template('pages/listings.html', listings=listings, user=user)

@app.route('/rent/<int:property_id>', methods=['POST'])
@login_required
def rent_property(property_id):
    user = User.query.get(current_user.id)
    property = Property.query.get_or_404(property_id)
    # Prevent landlord from renting their own property
    if property.user_id == user.id:
        flash('You cannot rent your own property.', 'danger')
        return redirect(url_for('listings'))
    if property.status not in ['For Rent', 'Available']:
        flash('This property is not available for rent.', 'danger')
        return redirect(url_for('listings'))
    # Prevent duplicate requests
    existing_request = RentalRequest.query.filter_by(user_id=user.id, property_id=property_id, status='Pending').first()
    if existing_request:
        flash('You already have a pending rental request for this property.', 'warning')
        return redirect(url_for('listings'))
    rental = RentalRequest(
        user_id=user.id,
        property_id=property_id,
        status='Pending'
    )
    db.session.add(rental)
    db.session.commit()
    flash('Rental request submitted!', 'success')
    return redirect(url_for('listings'))

@app.route('/rental/<int:rental_id>')
def rental_detail(rental_id):
    property = Property.query.get_or_404(rental_id)
    landlord = User.query.get(property.user_id)
    return render_template('pages/rental_detail.html', rental_id=rental_id, property=property, landlord=landlord)

@app.route('/messages')
@login_required
def messages():
    user = User.query.get(current_user.id)
    user_id = current_user.id
    sent = db.session.query(UserMessage.receiver_id).filter_by(sender_id=user_id)
    received = db.session.query(UserMessage.sender_id).filter_by(receiver_id=user_id)
    user_ids = set([uid for (uid,) in sent] + [uid for (uid,) in received])
    user_ids.discard(user_id)
    conversations = User.query.filter(User.id.in_(user_ids)).all() if user_ids else []
    other_id = request.args.get('user')
    messages_history = []
    other_user = None
    if other_id:
        other_user = User.query.get(int(other_id))
        messages_history = UserMessage.query.filter(
            db.or_(
                db.and_(UserMessage.sender_id==user_id, UserMessage.receiver_id==other_id),
                db.and_(UserMessage.sender_id==other_id, UserMessage.receiver_id==user_id)
            )
        ).order_by(UserMessage.timestamp.asc()).all()
        # Attach sender profile pic and name to each message
        for msg in messages_history:
            sender = User.query.get(msg.sender_id)
            msg.sender_profile_pic = sender.profile_pic if sender and sender.profile_pic else None
            msg.sender_name = sender.name if sender else "Unknown"
    return render_template(
        'pages/messages.html',
        user=user,
        conversations=conversations,
        messages_history=messages_history,
        other_user=other_user
    )

@app.route('/upload_message_file', methods=['POST'])
@login_required
def upload_message_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'}), 400
    filename = secure_filename(file.filename)
    save_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'chat_attachments')
    os.makedirs(save_dir, exist_ok=True)
    file.save(os.path.join(save_dir, filename))
    file_url = f'chat_attachments/{filename}'
    return jsonify({'success': True, 'file_url': file_url})

@app.route('/property/<int:property_id>/reviews', methods=['GET', 'POST'])
@login_required
def property_reviews(property_id):
    property = Property.query.get_or_404(property_id)
    if request.method == 'POST':
        content = request.form['content']
        rating = int(request.form['rating'])
        review = PropertyReview(
            property_id=property_id,
            user_id=current_user.id,
            content=content,
            rating=rating
        )
        db.session.add(review)
        db.session.commit()
        flash('Review submitted!')
        return redirect(url_for('property_reviews', property_id=property_id))
    reviews = PropertyReview.query.filter_by(property_id=property_id).order_by(PropertyReview.timestamp.desc()).all()
    return render_template('pages/property_reviews.html', property=property, reviews=reviews)

@app.route('/landlord/dashboard')
@login_required
def landlord_dashboard():
    if current_user.role != 'landlord':
        flash('Access denied.', 'danger')
        return redirect(url_for('landlord_dashboard'))
    user = User.query.get(current_user.id)
    properties = Property.query.filter_by(user_id=current_user.id).all()
    # Attach tenant info to each rental request
    for prop in properties:
        for req in prop.rental_requests:
            tenant = User.query.get(req.user_id)
            req.tenant_name = tenant.name if tenant else "Unknown"
            req.tenant_email = tenant.email if tenant else "Unknown"
    return render_template('pages/landlord_dashboard.html', properties=properties, user=user)

@app.route('/landlord/request_action/<int:request_id>/<action>', methods=['POST'])
@login_required
def landlord_request_action(request_id, action):
    rental_request = RentalRequest.query.get_or_404(request_id)
    property = rental_request.property
    if property.user_id != current_user.id:
        flash("Unauthorized.", "danger")
        return redirect(url_for('landlord_dashboard'))

    if action == 'accept':
        rental_request.status = 'accepted'
        property.status = 'Rented'  # <-- update property status
        # Optionally, reject all other pending requests for this property
        other_requests = RentalRequest.query.filter(
            RentalRequest.property_id == property.id,
            RentalRequest.id != rental_request.id,
            RentalRequest.status == 'Pending'
        ).all()
        for req in other_requests:
            req.status = 'rejected'
        db.session.commit()
        flash("Rental request accepted.", "success")
    elif action == 'reject':
        rental_request.status = 'rejected'
        db.session.commit()
        flash("Rental request rejected.", "warning")
    else:
        flash("Invalid action.", "danger")
        return redirect(url_for('landlord_dashboard'))

    return redirect(url_for('landlord_dashboard'))

@app.route('/landlord/delete/<int:property_id>', methods=['POST'])
@login_required
def delete_listing(property_id):
    if current_user.role != 'landlord':
        flash('Access denied.', 'danger')
        return redirect(url_for('landlord_dashboard'))
    property = Property.query.get_or_404(property_id)
    if property.user_id != current_user.id:
        flash('You do not have permission to delete this listing.', 'danger')
        return redirect(url_for('landlord_dashboard'))
    db.session.delete(property)
    db.session.commit()
    flash('Listing deleted successfully!', 'info')
    return redirect(url_for('landlord_dashboard'))

@app.route('/landlord/add', methods=['GET', 'POST'])
@login_required
def add_listing():
    if current_user.role != 'landlord':
        flash('Access denied.', 'danger')
        return redirect(url_for('landlord_dashboard'))
    user = User.query.get(current_user.id)
    if not user.verified:
        return render_template('pages/add_listing.html', user=user)
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        price = request.form.get('price')
        address = request.form.get('address')
        type_ = request.form.get('type')
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        user_id = current_user.id
        new_property = Property(
            title=title,
            description=description,
            price=price,
            address=address,
            type=type_,
            user_id=user_id,
            status='Available',
            verified=False
        )
        db.session.add(new_property)
        db.session.commit()
        if latitude and longitude:
            location = Location(
                property_id=new_property.id,
                latitude=float(latitude),
                longitude=float(longitude)
            )
            db.session.add(location)
        doc_types = ['land_title', 'tax_declaration', 'rpt_receipt', 'deed_of_sale', 'authorization_letter', 'owner_id', 'utility_bill', 'dti_sec', 'mayor_permit']
        for doc_type in doc_types:
            file = request.files.get(doc_type)
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{new_property.id}_{doc_type}_{file.filename}")
                file_path = os.path.join(PROPERTY_DOCS_FOLDER, filename)
                file.save(file_path)
                prop_doc = PropertyDocument(property_id=new_property.id, doc_type=doc_type, file_path=f'property_docs/{filename}')
                db.session.add(prop_doc)
        images = request.files.getlist('property_images')
        for img in images:
            if img and allowed_file(img.filename):
                filename = secure_filename(f"{new_property.id}_{img.filename}")
                file_path = os.path.join(PROPERTY_IMAGES_FOLDER, filename)
                img.save(file_path)
                image = Image(property_id=new_property.id, image_file=f'property_images/{filename}')
                db.session.add(image)
        db.session.commit()
        flash('Listing added successfully! Awaiting admin verification.', 'success')
        return redirect(url_for('landlord_dashboard'))
    return render_template('pages/add_listing.html', user=user)

@app.route('/landlord/edit/<int:property_id>', methods=['GET', 'POST'])
@login_required
def landlord_edit(property_id):
    if current_user.role != 'landlord':
        flash('Access denied.', 'danger')
        return redirect(url_for('landlord_dashboard'))
    property = Property.query.get_or_404(property_id)
    if property.user_id != current_user.id:
        flash('You do not have permission to edit this listing.', 'danger')
        return redirect(url_for('landlord_dashboard'))
    if request.method == 'POST':
        property.title = request.form.get('title')
        property.description = request.form.get('description')
        property.price = request.form.get('price')
        property.address = request.form.get('address')
        property.type = request.form.get('type')
        property.status = request.form.get('status')
        db.session.commit()
        flash('Listing updated successfully!', 'success')
        return redirect(url_for('landlord_dashboard'))
    return render_template('pages/landlord_edit.html', property=property)

@app.route('/select_lot', methods=['GET'])
@login_required
def select_lot():
    subdiv_dbf_path = os.path.join(os.getcwd(), 'shapefilesforbasemap', 'Subdivision.dbf')
    subdivisions = list(DBF(subdiv_dbf_path, load=True))
    subdiv_list = [dict(r) for r in subdivisions]
    subdiv_names = sorted(set(s['subd_name'] for s in subdiv_list if 'subd_name' in s))
    return render_template(
        'pages/select_lot.html',
        subdivisions=subdiv_names,
        subdiv_json=subdiv_list
    )

@app.route('/get_houses/<subd>', methods=['GET'])
@login_required
def get_houses(subd):
    dbf_map = {
        'vcdu': 'housevcdu.dbf',
        'sherwood': 'housesherwood.dbf',
        'rosewood1': 'houserosewood1.dbf',
        'princesh': 'houseprincesh.dbf',
        'miraville': 'housemiraville.dbf',
        'lumina': 'houselumina.dbf',
        'josephine': 'housejosephine.dbf',
        'idealhomes': 'houseidealhomes.dbf',
        'horizon': 'househorizon.dbf',
        'happyhomes': 'househappyhomes.dbf',
        'filinvest': 'housefilinvest.dbf',
        'fairmont': 'housefairmont.dbf',
        'camella1': 'housecamella1.dbf',
        'camella': 'housecamella.dbf'
    }
    key = subd.lower().replace(' ', '')
    filename = dbf_map.get(key)
    if not filename:
        return jsonify([])
    dbf_path = os.path.join(os.getcwd(), 'shapefilesforbasemap', filename)
    if not os.path.exists(dbf_path):
        return jsonify([])
    houses = list(DBF(dbf_path, load=True))
    return jsonify([dict(h) for h in houses])

@app.route('/geojson/<filename>')
@login_required
def geojson(filename):
    allowed = {
        'subdivision.geojson',
        'housevcdu.geojson',
        'housesherwood.geojson',
        'houserosewood1.geojson',
        'houseprincesh.geojson',
        'housemiraville.geojson',
        'houselumina.geojson',
        'housejosephine.geojson',
        'houseidealhomes.geojson',
        'househorizon.geojson',
        'househappyhomes.geojson',
        'housefilinvest.geojson',
        'housefairmont.geojson',
        'housecamella1.geojson',
        'housecamella.geojson'
    }
    if filename not in allowed:
        abort(404)
    return send_from_directory('shapefilesforbasemap', filename)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get(current_user.id)
    if request.method == 'POST':
        profile_pic = request.files.get('profile_pic')
        if profile_pic and allowed_file(profile_pic.filename):
            filename = secure_filename(f"{user.id}_{profile_pic.filename}")
            file_path = os.path.join(PROFILE_PICS_FOLDER, filename)
            profile_pic.save(file_path)
            user.profile_pic = f'profile_pics/{filename}'
            db.session.commit()
            flash('Profile picture updated.', 'success')
        for doc_type in ['id_front', 'id_back', 'selfie']:
            file = request.files.get(doc_type)
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{user.id}_{doc_type}_{file.filename}")
                file_path = os.path.join(USER_DOCS_FOLDER, filename)
                file.save(file_path)
                user_doc = UserDocument(user_id=user.id, doc_type=doc_type, file_path=f'user_docs/{filename}')
                db.session.add(user_doc)
        db.session.commit()
        flash('Documents uploaded. Please request verification if not yet requested.', 'info')
    user_docs = UserDocument.query.filter_by(user_id=user.id).all()
    return render_template('pages/profile.html', user=user, user_docs=user_docs)

@app.route('/request_verification', methods=['POST'])
@login_required
def request_verification():
    user = User.query.get(current_user.id)
    if not user.verified and not user.verification_requested:
        user.verification_requested = True
        db.session.commit()
        flash('Verification request sent. Please wait for admin approval.', 'info')
    return redirect(url_for('profile'))

@app.route('/api/map-data/<layer_name>')
def get_map_data(layer_name):
    import json
    data_path = os.path.join(app.static_folder, 'data', f'{layer_name}.geojson')
    if os.path.exists(data_path):
        with open(data_path, 'r') as f:
            return json.load(f)
    return {'error': 'Layer not found'}, 404

# --- Admin Routes ---
@app.route('/admin')
@login_required
def admin_dashboard():
    # Count properties that are not yet verified
    pending_listings_count = Property.query.filter_by(verified=False).count()
    users_count = User.query.count()
    rental_requests_count = RentalRequest.query.filter_by(status='Pending').count()
    flagged_listings_count = Property.query.filter_by(status='Flagged').count()
    recent_activity = AdminAction.query.order_by(AdminAction.date.desc()).limit(10).all()
    return render_template(
        'pages/admin_dashboard.html',
        pending_listings_count=pending_listings_count,
        users_count=users_count,
        rental_requests_count=rental_requests_count,
        flagged_listings_count=flagged_listings_count,
        recent_activity=recent_activity,
        User=User,
        Property=Property
    )

@app.route('/admin/listings')
@login_required
def admin_listings():
    listings = Property.query.all()
    return render_template('pages/admin_listings.html', listings=listings)

@app.route('/admin/listings/view/<int:listing_id>')
@login_required
def admin_view_listing(listing_id):
    listing = Property.query.get_or_404(listing_id)
    return render_template('pages/admin_view_listing.html', listing=listing)

@app.route('/admin/listings/verify/<int:listing_id>', methods=['POST'])
@login_required
def admin_verify_listing(listing_id):
    listing = Property.query.get_or_404(listing_id)
    listing.status = 'Verified'
    listing.verified = True
    db.session.commit()
    # Log admin action
    action = AdminAction(
        admin_id=current_user.id,
        property_id=listing.id,
        action='approved'
    )
    db.session.add(action)
    db.session.commit()
    flash('Listing verified successfully.', 'success')
    return redirect(url_for('admin_listings'))

@app.route('/admin/listings/reject/<int:listing_id>', methods=['POST'])
@login_required
def admin_reject_listing(listing_id):
    listing = Property.query.get_or_404(listing_id)
    # Log admin action before deleting
    action = AdminAction(
        admin_id=current_user.id,
        property_id=listing.id,
        action='rejected listing',
        target_name=listing.title
    )
    db.session.add(action)
    db.session.commit()
    db.session.delete(listing)
    db.session.commit()
    flash('Listing rejected and deleted.', 'danger')
    return redirect(url_for('admin_listings'))

@app.route('/admin/listings/edit/<int:listing_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_listing(listing_id):
    listing = Property.query.get_or_404(listing_id)
    if request.method == 'POST':
        listing.title = request.form['title']
        listing.description = request.form['description']
        listing.address = request.form['address']
        listing.price = request.form['price']
        listing.type = request.form['type']
        db.session.commit()
        flash('Listing updated.', 'success')
        return redirect(url_for('admin_listings'))
    return render_template('pages/admin_edit_listing.html', listing=listing)

@app.route('/admin/listings/delete/<int:listing_id>', methods=['POST'])
@login_required
def admin_delete_listing(listing_id):
    listing = Property.query.get_or_404(listing_id)
    db.session.delete(listing)
    db.session.commit()
    flash('Listing deleted.', 'info')
    return redirect(url_for('admin_listings'))

@app.route('/admin/users')
@login_required
def admin_users():
    users = User.query.all()
    return render_template('pages/admin_users.html', users=users)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.name = request.form['name']
        user.email = request.form['email']
        user.contact = request.form['contact']
        user.role = request.form['role']
        db.session.commit()
        flash('User updated.', 'success')
        return redirect(url_for('admin_users'))
    return render_template('pages/admin_edit_user.html', user=user)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    # Log admin action BEFORE deleting the user
    action_log = AdminAction(
        admin_id=current_user.id,
        user_id=user.id,
        action='deleted user',
        target_name=user.name
    )
    db.session.add(action_log)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted.', 'info')
    return redirect(url_for('admin_users'))

@app.route('/admin/requests')
@login_required
def admin_requests():
    requests = RentalRequest.query.order_by(RentalRequest.date.desc()).all()
    # Attach user and property objects for template
    enriched_requests = []
    for req in requests:
        req.user_obj = User.query.get(req.user_id)
        req.property_obj = Property.query.get(req.property_id)
        enriched_requests.append(req)
    return render_template('pages/admin_requests.html', requests=enriched_requests)

@app.route('/admin/requests/approve/<int:request_id>', methods=['POST'])
@login_required
def admin_approve_request(request_id):
    rental_request = RentalRequest.query.get_or_404(request_id)
    rental_request.status = 'Approved'
    property = Property.query.get(rental_request.property_id)
    property.status = 'Rented'
    db.session.commit()
    # Log admin action
    action_log = AdminAction(
        admin_id=current_user.id,
        property_id=property.id,
        user_id=rental_request.user_id,
        action='approved rental request'
    )
    db.session.add(action_log)
    db.session.commit()
    flash('Rental request approved.', 'success')
    return redirect(url_for('admin_requests'))


@app.route('/admin/requests/reject/<int:request_id>', methods=['POST'])
@login_required
def admin_reject_request(request_id):
    rental_request = RentalRequest.query.get_or_404(request_id)
    rental_request.status = 'Rejected'
    db.session.commit()
    # Log admin action
    action_log = AdminAction(
        admin_id=current_user.id,
        property_id=rental_request.property_id,
        user_id=rental_request.user_id,
        action='rejected rental request'
    )
    db.session.add(action_log)
    db.session.commit()
    flash('Rental request rejected.', 'danger')
    return redirect(url_for('admin_requests'))


@app.route('/admin/requests/view/<int:request_id>')
@login_required
def admin_view_request(request_id):
    request_obj = RentalRequest.query.get_or_404(request_id)
    request_obj.user_obj = User.query.get(request_obj.user_id)
    request_obj.property_obj = Property.query.get(request_obj.property_id)
    return render_template('pages/admin_view_request.html', request=request_obj)



@app.route('/admin/verify_users', methods=['GET', 'POST'])
@login_required
def admin_verify_users():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))
    if request.method == 'POST':
        user_id = int(request.form.get('user_id'))
        action = request.form.get('action')
        user = User.query.get(user_id)
        if user:
            if action == 'approve':
                user.verified = True
                user.verification_requested = False
                db.session.commit()
                # Log admin action
                action_log = AdminAction(
                    admin_id=current_user.id,
                    user_id=user.id,
                    action='approved user',
                    target_name=user.name
                )
                db.session.add(action_log)
                db.session.commit()
                # Send email notification
                send_verification_email(
                    user,
                    "Your RentEase account has been verified",
                    f"Hello {user.name},\n\nYour account has been verified by the admin. You can now use all features of RentEase.\n\nThank you!"
                )
                flash(f'User {user.name} verified.', 'success')
            elif action == 'reject':
                user.verification_requested = False
                db.session.commit()
                # Log admin action
                action_log = AdminAction(
                    admin_id=current_user.id,
                    user_id=user.id,
                    action='rejected user',
                    target_name=user.name
                )
                db.session.add(action_log)
                db.session.commit()
                flash(f'User {user.name} verification rejected.', 'info')
    pending_users = User.query.filter_by(verification_requested=True).all()
    return render_template('pages/admin_verify_users.html', pending_users=pending_users)

@app.route('/admin/verify_listings', methods=['GET', 'POST'])
@login_required
def admin_verify_listings():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))
    if request.method == 'POST':
        property_id = int(request.form.get('property_id'))
        action = request.form.get('action')
        prop = Property.query.get(property_id)
        if prop:
            if action == 'approve':
                prop.verified = True
                db.session.commit()
                # Log admin action
                action_log = AdminAction(
                    admin_id=current_user.id,
                    property_id=prop.id,
                    action='approved listing',
                    target_name=prop.title
                )
                db.session.add(action_log)
                db.session.commit()
                # Send email notification to property owner
                owner = User.query.get(prop.user_id)
                if owner:
                    send_verification_email(
                        owner,
                        "Your property listing has been verified",
                        f"Hello {owner.name},\n\nYour property listing '{prop.title}' has been verified and is now visible to users.\n\nThank you!"
                    )
                flash(f'Listing {prop.title} verified.', 'success')
            elif action == 'reject':
                # Log admin action before deleting
                action_log = AdminAction(
                    admin_id=current_user.id,
                    property_id=prop.id,
                    action='rejected listing',
                    target_name=prop.title
                )
                db.session.add(action_log)
                db.session.commit()
                db.session.delete(prop)
                db.session.commit()
                flash(f'Listing {prop.title} rejected and deleted.', 'info')
    pending_listings = Property.query.filter_by(verified=False).all()
    return render_template('pages/admin_verify_listings.html', pending_listings=pending_listings)




@socketio.on('join_room')
def handle_join_room(data):
    room = data['room']
    join_room(room)

@socketio.on('leave_room')
def handle_leave_room(data):
    room = data['room']
    leave_room(room)

@socketio.on('send_message')
def handle_send_message(data):
    sender_id = data['sender_id']
    receiver_id = data['receiver_id']
    content = data.get('content', '')
    room = data['room']
    attachment_url = data.get('attachment_url')
    msg = UserMessage(
        sender_id=sender_id,
        receiver_id=receiver_id,
        content=content,
        attachment_url=attachment_url
    )
    db.session.add(msg)
    db.session.commit()
    sender = User.query.get(sender_id)
    sender_profile_pic = sender.profile_pic if sender and sender.profile_pic else None
    sender_name = sender.name if sender else "Unknown"
    emit('receive_message', {
        'sender_id': sender_id,
        'receiver_id': receiver_id,
        'content': content,
        'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M'),
        'sender_profile_pic': sender_profile_pic,
        'sender_name': sender_name,
        'attachment_url': attachment_url
    }, room=room)

with app.app_context():
    db.create_all()
    from sqlalchemy import exists
    if not db.session.query(exists().where(User.email == 'admin@rentease.com')).scalar():
        admin = User(
            name='Admin',
            email='admin@rentease.com',
            password=generate_password_hash('admin321'),
            contact='0000000000',
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()



# --- Utility: Send OTP Email with SendGrid ---
def send_otp_email(to_email, otp_code):
    message = Mail(
        from_email=os.environ.get("MAIL_DEFAULT_SENDER", "nikuronishina@gmail.com"),
        to_emails=to_email,
        subject="Your OTP Code",
        plain_text_content=f"Your OTP code is {otp_code}",
    )
    try:
        sg = SendGridAPIClient(os.environ.get("SENDGRID_API_KEY"))
        response = sg.send(message)
        print(f"SendGrid response: {response.status_code}")
        return True
    except Exception as e:
        print(f"Error sending OTP: {e}")
        return False


if __name__ == '__main__':
    socketio.run(app, debug=True)
