from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, EqualTo

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with your actual secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    todos = db.relationship('Todo', backref='user', lazy=True)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    date = db.Column(db.String(10))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=20)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=20)])
    submit = SubmitField('Login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out!', 'info')
    return redirect(url_for('login'))

@app.route('/')
@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    todo_list = Todo.query.filter_by(user_id=user_id).all()
    return render_template("home.html", todo_list=todo_list)

@app.route('/todo')
def todo():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    todo_list = Todo.query.filter_by(user_id=user_id).all()
    return render_template("base.html", todo_list=todo_list)


@app.route('/add', methods=['POST'])
def add_todo():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    title = request.form.get("title")
    date = request.form.get("date")
    user_id = session['user_id']
    new_todo = Todo(title=title, complete=False, user_id=user_id ,date=date)
    db.session.add(new_todo)
    db.session.commit()
    todo_list = Todo.query.filter_by(user_id=user_id).all()
    return render_template("base.html", todo_list=todo_list)
    

# @app.route('/update/<int:todo_id>')
# def update_todo(todo_id):
#     if 'user_id' not in session:
#         return redirect(url_for('login'))
    
#     todo = Todo.query.filter_by(id=todo_id).first()
#     if todo:
#         todo.complete = not todo.complete
#         db.session.commit()
#     todo_list = Todo.query.filter_by(user_id=user_id).all()
#     return render_template("base.html", todo_list=todo_list)
#     #return redirect(url_for("home"))

# @app.route('/delete/<int:todo_id>')
# def delete_todo(todo_id):
#     if 'user_id' not in session:
#         return redirect(url_for('login'))
    
#     todo = Todo.query.filter_by(id=todo_id).first()
#     if todo:
#         db.session.delete(todo)
#         db.session.commit()
#     todo_list = Todo.query.filter_by(user_id=user_id).all()
#     return render_template("base.html", todo_list=todo_list)
#     #return redirect(url_for("home"))



@app.route('/update/<int:todo_id>')
def update_todo(todo_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    todo = Todo.query.filter_by(id=todo_id, user_id=user_id).first()
    if todo:
        todo.complete = not todo.complete
        db.session.commit()

    todo_list = Todo.query.filter_by(user_id=user_id).all()
    return render_template("base.html", todo_list=todo_list)

@app.route('/delete/<int:todo_id>')
def delete_todo(todo_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    todo = Todo.query.filter_by(id=todo_id, user_id=user_id).first()
    if todo:
        db.session.delete(todo)
        db.session.commit()

    todo_list = Todo.query.filter_by(user_id=user_id).all()
    return render_template("base.html", todo_list=todo_list)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
