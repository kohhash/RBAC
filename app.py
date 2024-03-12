from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from models import db, User
from forms import LoginForm
from flask_mail import Mail, Message
from forms import LoginForm, RegistrationForm, ForgotPasswordForm, PasswordResetForm

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['MAIL_SERVER'] = 'smtp.yourmailserver.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'al3rt.gpt'
app.config['MAIL_PASSWORD'] = 'W;PEFzf-T4qts=H'
app.config['MAIL_DEFAULT_SENDER'] = 'al3rt.gpt@proton.me'

mail = Mail(app)
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# with app.app_context():
#     db.create_all()
# exit(0)


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
            if user.confirmed:
                login_user(user)  # This should log the user in
                next_page = request.args.get('next')
                return redirect(next_page or url_for('home'))
            else:
                flash('Please confirm your account first.', 'warning')
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
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
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
        if user:
            token = user.generate_confirmation_token()
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


def send_email(to, subject, template, **kwargs):
    msg = Message(subject, recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    mail.send(msg)


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")
