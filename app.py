import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import current_app
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import SignatureExpired, BadSignature
from time import sleep
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User
from forms import LoginForm
from flask_mail import Mail, Message
from forms import LoginForm, RegistrationForm, ForgotPasswordForm, PasswordResetForm
import openai
import json
import jwt
import os
from functools import wraps
from dotenv import load_dotenv
from flask_cors import CORS
# from flask_wtf.csrf import CSRFProtect

# csrf = CSRFProtect()

app = Flask(__name__)
# csrf.init_app(app)
CORS(app, resources={r"/*": {"origins": "*",
     "methods": ["GET", "POST", "DELETE", "PUT", "PATCH"]}})

app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

# mail verification
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'yujikoyama485@gmail.com'
app.config['MAIL_PASSWORD'] = 'Qwe1234!@#$'
app.config['MAIL_DEFAULT_SENDER'] = 'yujikoyama485@gmail.com'

mail = Mail(app)

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

load_dotenv()
client = openai.OpenAI(api_key=os.environ.get("CHAT_GPT_API_KEY"))


def get_api_key():
    return client.api_key


class ToolCodeInterpreter:
    def __init__(self, type):
        self.type = type


class Assistant:
    def __init__(self, id, created_at, description, file_ids, instructions, metadata, model, name, object, tools):
        self.id = id
        self.created_at = created_at
        self.description = description
        self.file_ids = file_ids
        self.instructions = instructions
        self.metadata = metadata
        self.model = model
        self.name = name
        self.object = object
        self.tools = tools

# Function to convert your assistant data to the required format


def convert_to_json_format(assistants_list):
    assistants_data = []
    for assistant in assistants_list:
        # Convert each assistant to a dictionary
        assistant_dict = {
            "id": assistant.id,
            "object": assistant.object,
            "created_at": assistant.created_at,
            "name": assistant.name,
            "description": assistant.description,
            "model": assistant.model,
            "instructions": assistant.instructions,
            # Assuming all tools have a 'type' attribute
            "tools": [{"type": tool.type} for tool in assistant.tools],
            "file_ids": assistant.file_ids,
            "metadata": assistant.metadata
        }
        assistants_data.append(assistant_dict)

    # The outer structure that includes the list of assistants
    result_dict = {
        "object": "list",
        "data": assistants_data,
        "first_id": assistants_data[0]["id"] if assistants_data else None,
        "last_id": assistants_data[-1]["id"] if assistants_data else None,
        "has_more": False  # Set this according to whether there are more entries or not
    }

    # Convert to JSON string
    return json.dumps(result_dict, indent=2)  # Use indent for pretty-printing


def message_to_dict(message):
    return {
        'id': message.id,
        'assistant_id': message.assistant_id,
        'content': [{
            'text': content.text.value,
            'type': content.type
        } for content in message.content],
        'created_at': message.created_at,
        'file_ids': message.file_ids,
        'metadata': message.metadata,
        'object': message.object,
        'role': message.role,
        'run_id': message.run_id,
        'thread_id': message.thread_id
    }


@login_manager.user_loader
def load_user(user_id):
    print(user_id)
    return User.query.get(int(user_id))


@app.route('/')
@login_required
def home():
    # Control access based on role
    if current_user.role == 'admin':
        print("admin logged in")
        return render_template('homea.html')
        # admin access area
    elif current_user.role == 'premium':
        print("premium")
        # premium access area
    else:
        print("default")
        # default access area
    return render_template('home.html')

# login api for chrome extension


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.verify_password(form.password.data):
            print("user confirmed: ", user.confirmed)
            if user.confirmed:
                login_user(user)  # This should log the user in
                next_page = request.args.get('next')
                return redirect(next_page or url_for('home'))
            else:
                flash('Please confirm your account first.', 'warning')
                return render_template(
                    "email_verification_failed.html", email=user.email)
        else:
            flash('Invalid username or password.', 'danger')
            form.error.data = "Invalid username or password."
            render_template('login.html', title='Sign In', form=form)
    return render_template('login.html', title='Sign In', form=form)

# login api for desktop app


@app.route('/app/login', methods=['GET', 'POST'])
def app_login():
    if request.method == 'POST':
        username = password = ""
        try:
            username = request.form.get('username')
            password = request.form.get('password')
        except:
            username = request.get('username')
            password = request.get('password')
        print(username, ": ", password)
        user = User.find_by_username(username)
        if user and user.verify_password(password=password):
            # Generate an access token (JWT) upon successful login
            token = jwt.encode({
                'username': username,
                # Token expiration time
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=720)
            }, app.config['SECRET_KEY'])

            # enable this line in windows and disable in ubuntu(linux server)
            # token = token.decode('utf-8')
            print(token)
            # Login successful
            return jsonify({'message': 'Login successful', 'access_token': token}), 200
        else:
            # Login failed
            return jsonify({'message': 'Login failed'}), 401


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data, username=form.username.data)
        user.password = form.password.data

        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_verification_msg(
            [user.email], "Verification Email:", token=token, type='confirm')
        flash('A confirmation email has been sent to you by email.')
        return render_template('verify.html', email=user.email)
    return render_template('register.html', form=form)


@app.route('/confirm/<token>')
def confirm(token):
    s = Serializer(current_app.config['SECRET_KEY'])
    data = ''
    try:
        data = s.loads(token.encode('utf-8'))
    except:
        return False
    current_user = load_user(data.get('confirm'))
    if current_user.confirmed:
        return redirect(url_for('home'))
    if current_user.confirm(token):
        current_user.confirmed = True
        db.session.commit()
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('home'))


@app.route('/reset', methods=['GET', 'POST'])
def reset_request():
    if not current_user.is_anonymous:
        return redirect(url_for('home'))
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        try:
            if user:
                token = user.generate_reset_token()
                send_verification_msg(
                    [user.email], 'Reset Your Password', token=token, type='reset')
            flash(
                'An email with instructions to reset your password has been sent to you.')
            return render_template("verify-reset.html", email=user.email)
        except Exception as e:
            error = "MAIL_Server_not_found"
            if str(e).__contains__('NoneType'):
                error = "Not_a_registered_user"
            form.email.errors = error
            render_template('reset_request.html', form=form)
    return render_template('reset_request.html', form=form)


@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if not current_user.is_anonymous:
        return redirect(url_for('home'))
    s = Serializer(current_app.config['SECRET_KEY'])
    data = ''
    try:
        data = s.loads(token.encode('utf-8'))
    except:
        return False
    user = load_user(data.get('reset'))
    print(user)
    if not user:
        flash('That is an invalid or expired token')
        return redirect(url_for('reset_request'))
    form = PasswordResetForm()
    print(form)
    print(form.validate_on_submit())
    if form.validate_on_submit():
        print("reset validation")
        print(form.new_password.data)
        user.reset_password(token, form.new_password.data)
        user.password = form.new_password.data
        db.session.commit()
        flash('Your password has been updated!')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)


@app.route('/admin-users')
@login_required
def redirect_route():
    # Perform any necessary processing before the redirect
    # Redirect to the desired route or URL
    # Replace 'admin_users' with the actual route name
    return redirect(url_for('admin_users'))


@app.route('/admin/users')
@login_required
def admin_users():
    print(current_user.role)
    if current_user.role != 'admin':
        return redirect(url_for('home'))
    users = User.query.all()
    return render_template('admin_manage_users.html', users=users)


@app.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
def admin_add_user():
    if current_user.role != 'admin':
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.password = form.password.data
        user.role = 'default'  # Set the default role or let the admin choose
        db.session.add(user)
        db.session.commit()
        flash('User has been added.', 'success')
        return redirect(url_for('admin_users'))
    return render_template('register.html', form=form, title='Add User')


@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('home'))
    user = User.query.get_or_404(user_id)
    form = RegistrationForm(obj=user)
    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        # Do not change the password unless a new one has been entered
        if form.password.data:
            user.password = form.password.data
        db.session.commit()
        flash('The user has been updated.', 'success')
        return redirect(url_for('admin_users'))
    return render_template('register.html', form=form, title='Edit User')


@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('home'))
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('The user has been deleted.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/change-role/<int:user_id>', methods=['POST'])
@login_required
def admin_change_user_role(user_id):
    if current_user.role != 'admin':
        flash('You are not authorized to change user roles.', 'danger')
        return redirect(url_for('home'))

    user = User.query.get_or_404(user_id)
    new_role = request.form.get('new_role')

    if new_role not in ['admin', 'premium', 'default']:
        flash('Invalid role selected.', 'danger')
        return redirect(url_for('admin_users'))

    user.role = new_role
    db.session.commit()
    flash(f'User role updated to {new_role}.', 'success')
    return redirect(url_for('admin_users'))

# send_email(user.email, 'Confirm Your Account',
#            'email/confirm', user=user, token=token)


def send_verification_msg(recipients, subject, token, type):
    html_content = f"""
        <html>
            <head></head>
            <body>
                <p>Hi there!</p>
                <p>This is a verification message from our script.</p>
                <p>Please verify your account by clicking on the link below:</p>
                <a href="https://al3rt.me/{type}/{token}">Verify Account</a>
                <p>Thank you!</p>
            </body>
        </html>
        """
    """
    Sends a verification message to the given recipients with specified subject and HTML content
    """
    GMAIL_USERNAME = "al3rt.me.noreply"
    GMAIL_APP_PASSWORD = "hexc mzen fxmj lacp"

    # Create a multipart message
    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["To"] = ", ".join(recipients)
    msg["From"] = f"{GMAIL_USERNAME}@gmail.com"

    # Attach the HTML part
    part = MIMEText(html_content, 'html')
    msg.attach(part)

    try:
        # Connect to the Gmail SMTP server and send the email
        smtp_server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        smtp_server.login(GMAIL_USERNAME, GMAIL_APP_PASSWORD)
        smtp_server.sendmail(msg["From"], recipients, msg.as_string())
    except smtplib.SMTPException as e:
        print(f"An error occurred during SMTP communication: {e}")
    else:
        print("Verification email sent successfully!")
    finally:
        smtp_server.quit()

# openai API

# --------------  OpenAI APIs for chrome extension  ------------ #


@app.route('/openai', methods=['GET'])
@login_required
def openai_request():
    return "Server is ALIVE!"


@app.route('/openai/assistants/create', methods=['POST'])
@login_required
def openai_create_assistant():
    try:
        data = request.json
        instruction = data['instruction']
        assistant_name = data['assist-name']
        assistant_type = data['assist-type']

        print(instruction, assistant_name, assistant_type)
        my_assistant = client.beta.assistants.create(
            instructions=instruction,
            name=assistant_name,
            tools=[{"type": assistant_type}],
            model="gpt-4-0125-preview",
        )
        print(my_assistant)
        return "my_assistant successed"
    except openai.APIConnectionError as e:
        print("The server could not be reached")
        print(e.__cause__)
        return e.__cause__

    except openai.RateLimitError as e:
        return "A 429 status code was received; we should back off a bit."

    except openai.APIStatusError as e:
        print("Another non-200-range status code was received")
        print(e.status_code)
        print(e.response)
        return str(e.response)


@app.route('/openai/assistants', methods=['GET'])
@login_required
def openai_get_assistants():
    try:
        assistants = client.beta.assistants.list(
            order="desc",
            limit="20",
        )
        assistants = convert_to_json_format(assistants)
        return assistants
    except openai.APIConnectionError as e:
        print("The server could not be reached")
        print(e.__cause__)
        return str(e.__cause__)

    except openai.RateLimitError as e:
        return "A 429 status code was received; we should back off a bit."

    except openai.APIStatusError as e:
        print("Another non-200-range status code was received")
        print(e.response)
        return str(e.response)


@app.route('/openai/assistants/delete', methods=['DELETE'])
@login_required
def delete_assistant():
    try:
        assistant_id = request.json['asstid']
        response = client.beta.assistants.delete(assistant_id=assistant_id)
        if (response.deleted):
            return 'deleted'
        return 'delete failed'
    except openai.APIConnectionError as e:
        print("The server could not be reached")
        print(e.__cause__)
        return str(e.__cause__)

    except openai.RateLimitError as e:
        return "A 429 status code was received; we should back off a bit."

    except openai.APIStatusError as e:
        print("Another non-200-range status code was received")
        print(e.status_code)
        print(e.response)
        return str(e.response)


@app.route('/openai/assistants/modify', methods=['POST'])
@login_required
def modify_assistant():
    try:
        data = request.json
        assistant_id = data['asstid']
        instruction = data['instruction']
        assistant_name = data['assist-name']
        assistant_type = data['assist-type']
        updated_assistant = client.beta.assistants.update(
            assistant_id=assistant_id,
            instructions=instruction,
            name=assistant_name,
            tools=[{"type": assistant_type}],
            model="gpt-4-0125-preview",
        )

        print(updated_assistant)
        return 'modify successed'
    except openai.APIConnectionError as e:
        print("The server could not be reached")
        print(e.__cause__)
        return str(e.__cause__)

    except openai.RateLimitError as e:
        return "A 429 status code was received; we should back off a bit."

    except openai.APIStatusError as e:
        print("Another non-200-range status code was received")
        print(e.status_code)
        print(e.response)
        return str(e.response)


# threads
@app.route('/openai/threads/create', methods=['POST'])
@login_required
def openai_create_thread():
    try:
        _thread = client.beta.threads.create()
        return {"thdid": _thread.id}
    except openai.APIConnectionError as e:
        print("The server could not be reached")
        print(e.__cause__)
        return e.__cause__

    except openai.RateLimitError as e:
        return "A 429 status code was received; we should back off a bit."

    except openai.APIStatusError as e:
        print("Another non-200-range status code was received")
        print(e.status_code)
        print(e.response)
        return str(e.response)


@app.route('/openai/threads/delete', methods=['DELETE'])
@login_required
def delete_thread():
    try:
        thread_id = request.json['thdid']
        response = client.beta.threads.delete(thread_id=thread_id)
        print(response)
        if response.deleted:
            return 'deleted'
        return 'delete failed'
    except openai.APIConnectionError as e:
        print("The server could not be reached")
        print(e.__cause__)
        return str(e.__cause__)

    except openai.RateLimitError as e:
        return "A 429 status code was received; we should back off a bit."

    except openai.APIStatusError as e:
        print("Another non-200-range status code was received")
        print(e.status_code)
        print(e.response)
        return str(e.response)


@app.route('/openai/threads/modify', methods=['POST'])
@login_required
def modify_thread():
    try:
        data = request.json
        thread_id = data['thdid']
        user = data['user']
        updated_thread = client.beta.threads.update(
            thread_id=thread_id,
            metadata={
                "modified": "true",
                "user": user
            }
        )

        print(updated_thread)
        return 'modify successed'
    except openai.APIConnectionError as e:
        print("The server could not be reached")
        print(e.__cause__)
        return str(e.__cause__)

    except openai.RateLimitError as e:
        return "A 429 status code was received; we should back off a bit."

    except openai.APIStatusError as e:
        print("Another non-200-range status code was received")
        print(e.status_code)
        print(e.response)
        return str(e.response)


@app.route('/openai/run', methods=['POST'])
def run_assistant():
    try:
        data = request.json
        thread_id = data['thdid']
        assistant_id = data['asstid']
        content = data['content']
        print(thread_id, assistant_id, content)
        message = client.beta.threads.messages.create(
            thread_id=thread_id,
            role="user",
            content=content
        )

        run = client.beta.threads.runs.create(
            thread_id=thread_id,
            assistant_id=assistant_id,
        )

        run = client.beta.threads.runs.retrieve(
            thread_id=thread_id,
            run_id=run.id
        )
        messages = None
        role = "user"
        content = ""
        while role == "user" or len(content) == 0:
            sleep(0.5)
            print("getting msg again...")
            messages = client.beta.threads.messages.list(
                thread_id=thread_id,
                limit=1
            )
            role = message_to_dict(messages.data[0])["role"]
            if role == "assistant":
                content = message_to_dict(messages.data[0])["content"]
                if content:
                    content = content[0]["text"]
        messages_list_dicts = [message_to_dict(msg) for msg in messages.data]
        messages_json_str = json.dumps(messages_list_dicts, indent=4)
        messages_json_obj = json.loads(messages_json_str)
        messages_json_obj = [
            obj for obj in messages_json_obj if obj.get("role") != "user"]
        return messages_json_obj[0]
    except openai.APIConnectionError as e:
        print("The server could not be reached")
        print(e.__cause__)
        return str(e.__cause__)

    except openai.RateLimitError as e:
        return "A 429 status code was received; we should back off a bit."

    except openai.APIStatusError as e:
        print("Another non-200-range status code was received")
        print(e.status_code)
        print(e.response)
        return str(e.response)


@app.route('/openai/messages', methods=['POST'])
@login_required
def get_messages_from_thread():
    try:
        data = request.json
        thread_id = data['thdid']
        messages = client.beta.threads.messages.list(
            thread_id=thread_id,
            limit=2
        )
        messages_list_dicts = [message_to_dict(msg) for msg in messages.data]

        messages_json_str = json.dumps(messages_list_dicts, indent=4)

        messages_json_obj = json.loads(messages_json_str)
        print(messages_json_obj)
        return messages_json_obj
    except openai.APIConnectionError as e:
        print("The server could not be reached")
        print(e.__cause__)
        return str(e.__cause__)

    except openai.RateLimitError as e:
        return "A 429 status code was received; we should back off a bit."

    except openai.APIStatusError as e:
        print("Another non-200-range status code was received")
        print(e.status_code)
        print(e.response)
        return str(e.response)


# --------------  OpenAI APIs for Desktop App  ------------ #
# Define a decorator to require an access token for API endpoints
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = str(request.headers.get('Authorization'))[7:]
        print(type(token))
        print(token)
        if not token:
            # Unauthorized
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            print("try: exception part:")
            print(token)
            print(token.encode())
            data = jwt.decode(token, key=app.config['SECRET_KEY'], options={
                              "verify_signature": False})
            # Add additional token validation logic if needed
        except jwt.ExpiredSignatureError:
            # Unauthorized
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401  # Unauthorized

        return f(*args, **kwargs)

    return decorated_function


@app.route('/app/logout')
@token_required
def app_logout():
    try:
        logout_user()
        return jsonify({'message': 'Logout Succeed'}), 200
    except Exception as e:
        return jsonify({'message': str(e.__cause__)}), 401


@app.route('/app/openai', methods=['GET'])
@token_required
def app_openai_request():
    return "Server is ALIVE!"


@app.route('/app/openai/assistants/create', methods=['POST'])
@token_required
def app_openai_create_assistant():
    try:
        data = request.json
        instruction = data['instruction']
        assistant_name = data['assist-name']
        assistant_type = data['assist-type']

        print(instruction, assistant_name, assistant_type)
        my_assistant = client.beta.assistants.create(
            instructions=instruction,
            name=assistant_name,
            tools=[{"type": assistant_type}],
            model="gpt-4-0125-preview",
        )
        print(my_assistant)
        return "my_assistant successed"
    except openai.APIConnectionError as e:
        print("The server could not be reached")
        print(e.__cause__)
        return e.__cause__

    except openai.RateLimitError as e:
        return "A 429 status code was received; we should back off a bit."

    except openai.APIStatusError as e:
        print("Another non-200-range status code was received")
        print(e.status_code)
        print(e.response)
        return str(e.response)


@app.route('/app/openai/assistants', methods=['GET'])
@token_required
def app_openai_get_assistants():
    try:
        assistants = client.beta.assistants.list(
            order="desc",
            limit="20",
        )
        assistants = convert_to_json_format(assistants)
        return assistants
    except openai.APIConnectionError as e:
        print("The server could not be reached")
        print(e.__cause__)
        return str(e.__cause__)

    except openai.RateLimitError as e:
        return "A 429 status code was received; we should back off a bit."

    except openai.APIStatusError as e:
        print("Another non-200-range status code was received")
        print(e.response)
        return str(e.response)


@app.route('/app/openai/assistants/delete', methods=['DELETE'])
@token_required
def app_delete_assistant():
    try:
        assistant_id = request.json['asstid']
        response = client.beta.assistants.delete(assistant_id=assistant_id)
        if (response.deleted):
            return 'deleted'
        return 'delete failed'
    except openai.APIConnectionError as e:
        print("The server could not be reached")
        print(e.__cause__)
        return str(e.__cause__)

    except openai.RateLimitError as e:
        return "A 429 status code was received; we should back off a bit."

    except openai.APIStatusError as e:
        print("Another non-200-range status code was received")
        print(e.status_code)
        print(e.response)
        return str(e.response)


@app.route('/app/openai/assistants/modify', methods=['POST'])
@token_required
def app_modify_assistant():
    try:
        data = request.json
        assistant_id = data['asstid']
        instruction = data['instruction']
        assistant_name = data['assist-name']
        assistant_type = data['assist-type']
        updated_assistant = client.beta.assistants.update(
            assistant_id=assistant_id,
            instructions=instruction,
            name=assistant_name,
            tools=[{"type": assistant_type}],
            model="gpt-4-0125-preview",
        )

        print(updated_assistant)
        return 'modify successed'
    except openai.APIConnectionError as e:
        print("The server could not be reached")
        print(e.__cause__)
        return str(e.__cause__)

    except openai.RateLimitError as e:
        return "A 429 status code was received; we should back off a bit."

    except openai.APIStatusError as e:
        print("Another non-200-range status code was received")
        print(e.status_code)
        print(e.response)
        return str(e.response)


# threads
@app.route('/app/openai/threads/create', methods=['POST'])
@token_required
def app_openai_create_thread():
    try:
        _thread = client.beta.threads.create()
        return {"thdid": _thread.id}
    except openai.APIConnectionError as e:
        print("The server could not be reached")
        print(e.__cause__)
        return e.__cause__

    except openai.RateLimitError as e:
        return "A 429 status code was received; we should back off a bit."

    except openai.APIStatusError as e:
        print("Another non-200-range status code was received")
        print(e.status_code)
        print(e.response)
        return str(e.response)


@app.route('/app/openai/threads/delete', methods=['DELETE'])
@token_required
def app_delete_thread():
    try:
        thread_id = request.json['thdid']
        response = client.beta.threads.delete(thread_id=thread_id)
        print(response)
        if response.deleted:
            return 'deleted'
        return 'delete failed'
    except openai.APIConnectionError as e:
        print("The server could not be reached")
        print(e.__cause__)
        return str(e.__cause__)

    except openai.RateLimitError as e:
        return "A 429 status code was received; we should back off a bit."

    except openai.APIStatusError as e:
        print("Another non-200-range status code was received")
        print(e.status_code)
        print(e.response)
        return str(e.response)


@app.route('/app/openai/threads/modify', methods=['POST'])
@token_required
def app_modify_thread():
    try:
        data = request.json
        thread_id = data['thdid']
        user = data['user']
        updated_thread = client.beta.threads.update(
            thread_id=thread_id,
            metadata={
                "modified": "true",
                "user": user
            }
        )

        print(updated_thread)
        return 'modify successed'
    except openai.APIConnectionError as e:
        print("The server could not be reached")
        print(e.__cause__)
        return str(e.__cause__)

    except openai.RateLimitError as e:
        return "A 429 status code was received; we should back off a bit."

    except openai.APIStatusError as e:
        print("Another non-200-range status code was received")
        print(e.status_code)
        print(e.response)
        return str(e.response)


@app.route('/app/openai/run', methods=['POST'])
@token_required
def app_run_assistant():
    try:
        data = request.json
        thread_id = data['thdid']
        assistant_id = data['asstid']
        content = data['content']
        print(thread_id, assistant_id, content)
        message = client.beta.threads.messages.create(
            thread_id=thread_id,
            role="user",
            content=content
        )

        run = client.beta.threads.runs.create(
            thread_id=thread_id,
            assistant_id=assistant_id,
        )

        run = client.beta.threads.runs.retrieve(
            thread_id=thread_id,
            run_id=run.id
        )
        messages = None
        role = "user"
        content = ""
        while role == "user" or len(content) == 0:
            sleep(0.5)
            print("getting msg again...")
            messages = client.beta.threads.messages.list(
                thread_id=thread_id,
                limit=1
            )
            role = message_to_dict(messages.data[0])["role"]
            if role == "assistant":
                content = message_to_dict(messages.data[0])["content"]
                if content:
                    content = content[0]["text"]
        messages_list_dicts = [message_to_dict(msg) for msg in messages.data]
        messages_json_str = json.dumps(messages_list_dicts, indent=4)
        messages_json_obj = json.loads(messages_json_str)
        messages_json_obj = [
            obj for obj in messages_json_obj if obj.get("role") != "user"]
        return messages_json_obj[0]
    except openai.APIConnectionError as e:
        print("The server could not be reached")
        print(e.__cause__)
        return str(e.__cause__)

    except openai.RateLimitError as e:
        return "A 429 status code was received; we should back off a bit."

    except openai.APIStatusError as e:
        print("Another non-200-range status code was received")
        print(e.status_code)
        print(e.response)
        return str(e.response)


@app.route('/app/openai/messages', methods=['POST'])
@token_required
def app_get_messages_from_thread():
    try:
        data = request.json
        thread_id = data['thdid']
        messages = client.beta.threads.messages.list(
            thread_id=thread_id,
            limit=2
        )
        messages_list_dicts = [message_to_dict(msg) for msg in messages.data]

        messages_json_str = json.dumps(messages_list_dicts, indent=4)

        messages_json_obj = json.loads(messages_json_str)
        print(messages_json_obj)
        return messages_json_obj
    except openai.APIConnectionError as e:
        print("The server could not be reached")
        print(e.__cause__)
        return str(e.__cause__)

    except openai.RateLimitError as e:
        return "A 429 status code was received; we should back off a bit."

    except openai.APIStatusError as e:
        print("Another non-200-range status code was received")
        print(e.status_code)
        print(e.response)
        return str(e.response)


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")
