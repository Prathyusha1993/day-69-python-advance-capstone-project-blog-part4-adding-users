from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm


'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# for adding profile images to comment section
gravatar = Gravatar(app,
                    size=100,
                    default='retro',
                    rating='g',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)
# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

@app.before_request
def log_request_info():
    print("Before request function triggered")  # Debugging
    print(f"URL: {request.url} | Method: {request.method}")

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

# TODO: Create a User table for all your registered users.
class User(UserMixin, db.Model):
    __tablename__='users'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))
    posts = relationship('BlogPost', back_populates='author')
    comments = relationship('Comment', back_populates='comment_author')

# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    author = relationship('User', back_populates='posts')
    comments=relationship('Comment', back_populates='parent_post')

class Comment(db.Model):
    __tablename__='comments'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    # Child relationship:"users.id" The users refers to the tablename of the User class.
    # "comments" refers to the comments property in the User class.
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('users.id'))
    comment_author = relationship('User', back_populates='comments')
    # Child Relationship to the BlogPosts
    post_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('blog_posts.id'))
    parent_post = relationship('BlogPost', back_populates='comments')


with app.app_context():
    db.create_all()

# Create an admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # if id is not equal to 1 then abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # otherwise continue with route function
        return f(*args, **kwargs)
    return decorated_function


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=['GET', 'POST'])
def register():
    try:
        print(request.url)
        register_form = RegisterForm()
        if register_form.validate_on_submit():
            email = register_form.email.data
            result = db.session.execute(db.select(User).where(User.email == email))
            user = result.scalar()
            if user:
                # aleardy exists
                flash("You've already signed up with that email, log in instead.!")
                return redirect(url_for('login'))

            hash_and_salted_password = generate_password_hash(
                register_form.password.data,
                method='pbkdf2:sha256',
                salt_length=8
            )
            new_user = User(
                email=register_form.email.data,
                name=register_form.name.data,
                password=hash_and_salted_password
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
        return render_template("register.html", form=register_form, logged_in=current_user.is_authenticated)
    except Exception as e:
        print(f"Error: {e}")  # Print error details
        return "An error occurred, check the logs.", 500


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        print(request.url)
        login_form = LoginForm()
        if login_form.validate_on_submit():
            email=login_form.email.data
            password=login_form.password.data

            result = db.session.execute(db.select(User).where(User.email == email))
            user = result.scalar()

            # email doesnt exists nad password incorrect case
            if not user:
                flash('That email doesnt exists, please try again.')
                return redirect(url_for('login'))
            # check stored password hash against entered password hashed
            elif not check_password_hash(user.password, password):
                flash('Password Incorrect, please try again.')
                return redirect(url_for('login'))
            else:
                login_user(user)
                return redirect(url_for('get_all_posts'))

        return render_template("login.html", form=login_form, logged_in=current_user.is_authenticated)
    except Exception as e:
        print(f"Error: {e}")  # Print error details
        return "An error occurred, check the logs.", 500


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

# @app.route('/')
# def home():
#     return 'hello world!'


@app.route('/')
def get_all_posts():
    try:
        print(request.url)
        result = db.session.execute(db.select(BlogPost))
        posts = result.scalars().all()
        return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)
    except Exception as e:
        print(f"Error: {e}")  # Print error details
        return "An error occurred, check the logs.", 500


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash('You need to login or register to comment')
            return redirect(url_for('login'))
        new_comment = Comment(
            text=comment_form.comment_text.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        # return redirect(url_for('show_post', post_id=post_id))
    return render_template("post.html", post=requested_post, form=comment_form)




# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
