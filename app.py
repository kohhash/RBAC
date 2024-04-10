from time import sleep
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User
from forms import LoginForm
# from flask_mail import Mail, Message
from forms import LoginForm, RegistrationForm, ForgotPasswordForm, PasswordResetForm
import openai
import json
import os
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
# app.config['MAIL_SERVER'] = 'smtp.yourmailserver.com'
# app.config['MAIL_PORT'] = 587
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USERNAME'] = 'Yuji Koyama'
# app.config['MAIL_PASSWORD'] = 'Qwe1234!@#$'
# app.config['MAIL_DEFAULT_SENDER'] = 'yujikoyama485@gmail.com'

# mail = Mail(app)
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
        return render_template('home.html')
        # admin access area
    elif current_user.role == 'premium':
        print("premium")
        # premium access area
    else:
        print("default")
        # default access area
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.verify_password(form.password.data):
            # if user.confirmed:
            login_user(user)  # This should log the user in
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
            # else:
            # flash('Please confirm your account first.', 'warning')
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html', title='Sign In', form=form)


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
        user.confirmed = 1
        db.session.add(user)
        db.session.commit()
        # token = user.generate_confirmation_token()
        # send_email(user.email, 'Confirm Your Account',
        #            'email/confirm', user=user, token=token)
        flash('A confirmation email has been sent to you by email.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('home'))
    if current_user.confirm(token):
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
        # if user:
        # token = user.generate_confirmation_token()
        # send_email(user.email, 'Reset Your Password',
        #            'email/reset_password', token=token)
        flash('An email with instructions to reset your password has been sent to you.')
        return redirect(url_for('login'))
    return render_template('reset_request.html', form=form)


@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if not current_user.is_anonymous:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if not user:
        flash('That is an invalid or expired token')
        return redirect(url_for('reset_request'))
    form = PasswordResetForm()
    if form.validate_on_submit():
        user.password = form.new_password.data
        db.session.commit()
        flash('Your password has been updated!')
        return redirect(url_for('login'))
    return render_template('reset_token.html', form=form)


@app.route('/admin-users')
@login_required
def redirect_route():
    print("admin users////")
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
    print(len(users))
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

# def send_email(to, subject, template, **kwargs):
#     msg = Message(subject, recipients=[to])
#     msg.body = render_template(template + '.txt', **kwargs)
#     msg.html = render_template(template + '.html', **kwargs)
#     mail.send(msg)

# openai API


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


if __name__ == '__main__':
    app.run(debug=True, port=80, host="0.0.0.0")
