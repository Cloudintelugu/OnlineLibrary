from flask import Flask, request, render_template, redirect, session, url_for
import pymysql
import boto3
import os
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import base64
from botocore.exceptions import ClientError
import bcrypt

# Load environment variables from .env file
load_dotenv('appsettings.env')

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your_default_secret_key')  # Load from environment variable

# MySQL configuration - use environment variables
db_host = os.getenv('DB_HOST')
db_user = os.getenv('DB_USER')
db_password = os.getenv('DB_PASSWORD')
db_name = os.getenv('DB_NAME')
s3_Key = os.getenv('AWS_ACCESS_KEY_ID')
s3_SecKey = os.getenv('AWS_SECRET_ACCESS_KEY')
s3_bucket = os.getenv('S3_BUCKET')
s3_region = os.getenv('S3_REGION')
app_Env = os.getenv('Env')

# AWS KMS configuration
kms_key_id = os.getenv('KMS_KEY')  # Replace with your actual KMS Key ID
kms_client = boto3.client('kms', region_name=s3_region)

# Initialize AWS S3 client
s3 = boto3.client('s3', aws_access_key_id=s3_Key, aws_secret_access_key=s3_SecKey, region_name=s3_region)

# Initialize MySQL connection
db = pymysql.connect(host=db_host, user=db_user, password=db_password, database=db_name)

# Folder to store uploads (inside static folder for easy access)
UPLOAD_FOLDER = os.path.join(app.root_path, 'static/uploads/')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Allowed file extensions for image upload
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Function to validate file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def encrypt_password_kms(plain_text_password):
    try:
        response = kms_client.encrypt(
            KeyId=kms_key_id,
            Plaintext=plain_text_password.encode('utf-8')
        )
        encrypted_password = base64.b64encode(response['CiphertextBlob']).decode('utf-8')
        return encrypted_password
    except ClientError as e:
        print(f"Encryption failed: {e}")
        return None

def decrypt_password_kms(encrypted_password):
    try:
        # Decode the base64 encoded encrypted password
        decoded_encrypted_password = base64.b64decode(encrypted_password.encode('utf-8'))
        
        # Decrypt the password using KMS
        response = kms_client.decrypt(
            CiphertextBlob=decoded_encrypted_password
        )
        
        # The decrypted password is returned as bytes, decode it to string
        decrypted_password = response['Plaintext'].decode('utf-8')
        return decrypted_password
    except ClientError as e:
        print(f"Decryption failed: {e}")
        return None

@app.route('/')
def index():
    # Clear session if needed
    session.pop('username', None)
    session.pop('email', None)
    session.pop('image_url', None)
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password'].encode('utf-8')  # Encode to bytes
        image = request.files['image']

        if app_Env == '0':  # Store locally if environment is '0'
            if image and allowed_file(image.filename):
                hashed_password = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')
                filename = secure_filename(image.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                # Ensure the uploads directory exists
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

                image.save(file_path)  # Save the file locally

                # Store the relative file path in the database
                relative_path = "uploads/{}".format(filename)
                cursor = db.cursor()
                cursor.execute(
                    "INSERT INTO users (name, email, password, image_url) VALUES (%s, %s, %s, %s)",
                    (name, email, hashed_password, relative_path)
                )
                db.commit()
                cursor.close()
                return redirect('/signin')
        else:  # Store on S3 if environment is not '0'
            if image and allowed_file(image.filename):
                filename = secure_filename(image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                encrypted_password = encrypt_password_kms(password.decode('utf-8'))

                # Upload image to S3
                s3.upload_file(
                    os.path.join(app.config['UPLOAD_FOLDER'], filename),
                    s3_bucket,
                    filename,
                    ExtraArgs={'ACL': 'public-read'}
                )

                # Get the image URL from S3
                image_url = f"https://{s3_bucket}.s3.{s3_region}.amazonaws.com/{filename}"

                # Insert user data into RDS MySQL
                cursor = db.cursor()
                cursor.execute(
                    "INSERT INTO users (name, email, password, image_url) VALUES (%s, %s, %s, %s)",
                    (name, email, encrypted_password, image_url)
                )
                db.commit()
                cursor.close()

                # Clean up the uploaded image file from local storage
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                return redirect('/signin')

    return render_template('signup.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode('utf-8')  # Encode the password for comparison

        # Retrieve user data from the database
        cursor = db.cursor()
        cursor.execute("SELECT password, name, email, image_url FROM users WHERE email = %s", (email,))
        result = cursor.fetchone()
        cursor.close()

        if result:
            stored_password = result[0]  # Encrypted or hashed password

            if app_Env == '0':
                # Verify the password using bcrypt
                if bcrypt.checkpw(password, stored_password.encode('utf-8')):
                    session['username'] = result[1]
                    session['email'] = result[2]
                    session['image_url'] = result[3]  # Local file path or S3 URL
                    return redirect('/welcome')
                else:
                    return "Invalid Credentials!"

            elif app_Env == '1':
                # Decrypt the password using AWS KMS and compare it
                decrypted_password = decrypt_password_kms(stored_password)
                if decrypted_password and decrypted_password.encode('utf-8') == password:  # Compare decrypted password
                    session['username'] = result[1]
                    session['email'] = result[2]
                    session['image_url'] = result[3]  # S3 URL
                    return redirect('/welcome')
                else:
                    return "Invalid Credentials!"

        return "Invalid Credentials!"  # If no user is found or password doesn't match

    return render_template('signin.html')

@app.route('/welcome')
def welcome():
    # Check if the user is logged in
    if 'username' not in session:
        return redirect(url_for('signin'))

    if app_Env == '0':  # Serve from local if app_Env is '0'
        image_url = url_for('static', filename=session['image_url'])
    else:
        image_url = session['image_url']  # Use S3 URL

    return render_template('welcome.html', username=session['username'], email=session['email'], image_url=image_url)

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('email', None)
    session.pop('image_url', None)
    return redirect('/')

if __name__ == '__main__':
    # Ensure uploads directory exists
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    app.run(host='0.0.0.0', port=5000, debug=True)  # Change to port 80 for HTTP access
