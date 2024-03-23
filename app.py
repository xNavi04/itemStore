import werkzeug.security
from flask import Flask, render_template, request, redirect, url_for, abort, send_file, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash
from flask_ckeditor import CKEditor
from flask_bootstrap import Bootstrap5
from forms import categoriesForm, storesForm, borrowForm, itemForm, itemFormForBorrow, selectCategoryForm, selectStoreForm, confirmReturnForm, addPermissionToUserForm, inputChildrenForm, dateForm, addAcitivityForm, endAcitivityForm, ipetForm, dateSegregatorForm, lateSegregatorForm, missSegregatorForm, selectForm, therapyForm, teacherForm, managementForm
from datetime import datetime
from functools import wraps
from parse import add_or_update_param, remove_last_param, check_filter
import os
import pandas as pd

def my_len(value):
    return len(value)


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URI")


db = SQLAlchemy()
db.init_app(app)
login_manager = LoginManager(app)
login_manager.init_app(app)
CKEditor(app)
Bootstrap5(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

###########-------------DATABASE-------------#####################
user_permissions = db.Table('user_permissions',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.id'), primary_key=True)
)

child_therapies = db.Table('child_therapies',
    db.Column('child_id', db.Integer, db.ForeignKey('children.id'), primary_key=True),
    db.Column('therapy_id', db.Integer, db.ForeignKey('therapies.id'), primary_key=True)
)

child_teachers = db.Table('child_teachers',
    db.Column('child_id', db.Integer, db.ForeignKey('children.id'), primary_key=True),
    db.Column('teacher_id', db.Integer, db.ForeignKey('teachers.id'), primary_key=True)
)

class Management(db.Model):
    __tablename__ = "managements"
    id = db.Column(db.Integer, primary_key=True)
    child_id = db.Column(db.Integer, db.ForeignKey("children.id"))
    name = db.Column(db.String, nullable=False)
    child = db.relationship("Child", back_populates="managements")


class Teacher(db.Model):
    __tablename__ = "teachers"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)


class Therapy(db.Model):
    __tablename__ = "therapies"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False, unique=True)


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    image = db.Column(db.String)
    image_mimetype = db.Column(db.String)
    items = db.relationship("Item", back_populates="user")
    categories = db.relationship("Category", back_populates="user")
    stores = db.relationship("Store", back_populates="user")
    borrows = db.relationship("Borrow", back_populates="user")
    permissions = db.relationship('Permission', secondary=user_permissions, backref=db.backref('users', lazy='dynamic'))

class Permission(db.Model):
    __tablename__ = "permissions"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)

class Item(db.Model):
    __tablename__ = "items"
    id = db.Column(db.Integer, primary_key=True)
    category_id = db.Column(db.Integer, db.ForeignKey("categories.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    store_id = db.Column(db.Integer, db.ForeignKey("store.id"))
    title = db.Column(db.String, nullable=False)
    author = db.Column(db.String, nullable=False)
    data = db.Column(db.String, nullable=False)
    status = db.Column(db.String, nullable=False)
    user = db.relationship("User", back_populates="items")
    category = db.relationship("Category", back_populates="items")
    store = db.relationship("Store", back_populates="items")
    borrow = db.relationship("Borrow", back_populates="item")

class Borrow(db.Model):
    __tablename__ = "borrows"
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey("items.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    start_date = db.Column(db.String, nullable=False)
    to_date = db.Column(db.String, nullable=False)
    borrower = db.Column(db.String, nullable=False)
    item = db.relationship("Item", back_populates="borrow")
    user = db.relationship("User", back_populates="borrows")

class Category(db.Model):
    __tablename__ = "categories"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    name = db.Column(db.String, nullable=False)
    data = db.Column(db.String, nullable=False)
    user = db.relationship("User", back_populates="categories")
    items = db.relationship("Item", back_populates="category")

class Store(db.Model):
    __tablename__ = "store"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    name = db.Column(db.String, nullable=False)
    user = db.relationship("User", back_populates="stores")
    items = db.relationship("Item", back_populates="store")


class Agreement(db.Model):
    __tablename__ = "agreements"
    id = db.Column(db.Integer, primary_key=True)
    child_id = db.Column(db.Integer, db.ForeignKey("children.id"))
    name = db.Column(db.String(30), nullable=False, unique=True)
    date = db.Column(db.DateTime, nullable=False)
    child = db.relationship("Child", back_populates="agreements")


class WOFU(db.Model):
    __tablename__ = "wofus"
    id = db.Column(db.Integer, primary_key=True)
    child_id = db.Column(db.Integer, db.ForeignKey("children.id"))
    name = db.Column(db.String(30), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    child = db.relationship("Child", back_populates="wofus")

class ExpirationDate(db.Model):
    __tablename__ = "expiration_dates"
    id = db.Column(db.Integer, primary_key=True)
    child_id = db.Column(db.Integer, db.ForeignKey("children.id"))
    name = db.Column(db.String(30), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    copy = db.Column(db.Boolean)
    child = db.relationship("Child", back_populates="expiration_dates")

class Activity(db.Model):
    __tablename__ = "activities"
    id = db.Column(db.Integer, primary_key=True)
    child_id = db.Column(db.Integer, db.ForeignKey("children.id"))
    name = db.Column(db.String(30), nullable=False)
    card = db.Column(db.Boolean)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime)
    child = db.relationship("Child", back_populates="activities")

class Child(db.Model):
    __tablename__ = "children"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    birth = db.Column(db.Date, nullable=False)
    copy_document = db.Column(db.Boolean)
    IPET = db.Column(db.Date)
    activities = db.relationship("Activity", back_populates="child", cascade='all, delete-orphan')
    agreements = db.relationship("Agreement", back_populates="child", cascade='all, delete-orphan')
    wofus = db.relationship("WOFU", back_populates="child", cascade='all, delete-orphan')
    expiration_dates = db.relationship("ExpirationDate", back_populates="child", cascade='all, delete-orphan')
    therapies = db.relationship('Therapy', secondary=child_therapies, backref=db.backref('therapies', lazy='dynamic'))
    teachers = db.relationship('Teacher', secondary=child_teachers, backref=db.backref('teachers', lazy='dynamic'))
    managements = db.relationship("Management", back_populates="child")



with app.app_context():
    db.create_all()
    if not db.session.execute(db.select(Permission)).scalar():
        new_permission = Permission(name="czytanie przedmioty")
        db.session.add(new_permission)
        new_permission = Permission(name="edycja przedmioty")
        db.session.add(new_permission)
        new_permission = Permission(name="usuwanie przedmioty")
        db.session.add(new_permission)
        new_permission = Permission(name="dodawanie przedmioty")
        db.session.add(new_permission)
        new_permission = Permission(name="czytanie dzieci")
        db.session.add(new_permission)
        new_permission = Permission(name="edycja dzieci")
        db.session.add(new_permission)
        new_permission = Permission(name="usuwanie dzieci")
        db.session.add(new_permission)
        new_permission = Permission(name="dodawanie dzieci")
        db.session.add(new_permission)
        db.session.commit()
    if not db.session.execute(db.select(User)).scalar():
        password = werkzeug.security.generate_password_hash("Admin1230")
        admin = User(username="Admin", email="admin@gmail.com", password=password)
        db.session.add(admin)
        db.session.commit()

###########-------------DATABASE-------------#####################



def confirmPassword(f):
    @wraps(f)
    def decorator_function(*args, **kwargs):
        alerts = []
        form = confirmReturnForm()
        if form.validate_on_submit():
            if check_password_hash(current_user.password, form.password.data):
                return f(*args, **kwargs)
            else:
                alerts.append("Złe hasło!")
        content = {
            "logged_in": current_user.is_authenticated,
            "categories": db.session.execute(db.select(Category)).scalars().all(),
            "stores": db.session.execute(db.select(Store)).scalars().all(),
            "alerts": alerts,
            "form": form
        }
        return render_template("addItem.html", **content)
    return decorator_function


def adminOnly(f):
    @wraps(f)
    def decorator_function(*args, **kwargs):
        if current_user.id == 1:
            return f(*args, **kwargs)
        else:
            return abort(404)
    return decorator_function


def getData(f):
    @wraps(f)
    def decorator_function(*args, **kwargs):
        if not current_user.is_authenticated:
            kwargs["all_permissions"] = []
        elif current_user.id == 1:
            kwargs["all_permissions"] = [permission.name for permission in db.session.execute(db.select(Permission)).scalars().all()]
        else:
            kwargs["all_permissions"] = [permission.name for permission in current_user.permissions]
        return f(*args, **kwargs)
    return decorator_function

def reading(f):
    @wraps(f)
    def decorator_function(*args, **kwargs):
        if current_user.id == 1:
            return f(*args, **kwargs)
        if not current_user.permissions:
            return abort(404)
        if "czytanie przedmioty" in [permission.name for permission in current_user.permissions or current_user.id == 1]:
            return f(*args, **kwargs)
        else:
            return abort(404)
    return decorator_function


def editing(f):
    @wraps(f)
    def decorator_function(*args, **kwargs):
        if current_user.id == 1:
            return f(*args, **kwargs)
        if not current_user.permissions:
            return abort(404)
        if "edycja przedmioty" in [permission.name for permission in current_user.permissions] or current_user.id == 1:
            return f(*args, **kwargs)
        else:
            return abort(404)
    return decorator_function


def adding(f):
    @wraps(f)
    def decorator_function(*args, **kwargs):
        if current_user.id == 1:
            return f(*args, **kwargs)
        if not current_user.permissions:
            return abort(404)
        if "dodawanie przedmioty" in [permission.name for permission in current_user.permissions] or current_user.id == 1:
            return f(*args, **kwargs)
        else:
            return abort(404)
    return decorator_function

def deleting(f):
    @wraps(f)
    def decorator_function(*args, **kwargs):
        if current_user.id == 1:
            return f(*args, **kwargs)
        if not current_user.permissions:
            return abort(404)
        if "usuwanie przedmioty" in [permission.name for permission in current_user.permissions] or current_user.id == 1:
            return f(*args, **kwargs)
        else:
            return abort(404)
    return decorator_function

def reading_dzieci(f):
    @wraps(f)
    def decorator_function(*args, **kwargs):
        if current_user.id == 1:
            return f(*args, **kwargs)
        if not current_user.permissions:
            return abort(404)
        if "czytanie dzieci" in [permission.name for permission in current_user.permissions or current_user.id == 1]:
            return f(*args, **kwargs)
        else:
            return abort(404)
    return decorator_function


def editing_child(f):
    @wraps(f)
    def decorator_function(*args, **kwargs):
        if current_user.id == 1:
            return f(*args, **kwargs)
        if not current_user.permissions:
            return abort(404)
        if "edycja dzieci" in [permission.name for permission in current_user.permissions] or current_user.id == 1:
            return f(*args, **kwargs)
        else:
            return abort(404)
    return decorator_function


def adding_child(f):
    @wraps(f)
    def decorator_function(*args, **kwargs):
        if current_user.id == 1:
            return f(*args, **kwargs)
        if not current_user.permissions:
            return abort(404)
        if "dodawanie dzieci" in [permission.name for permission in current_user.permissions] or current_user.id == 1:
            return f(*args, **kwargs)
        else:
            return abort(404)
    return decorator_function

def deleting_child(f):
    @wraps(f)
    def decorator_function(*args, **kwargs):
        if current_user.id == 1:
            return f(*args, **kwargs)
        if not current_user.permissions:
            return abort(404)
        if "usuwanie dzieci" in [permission.name for permission in current_user.permissions] or current_user.id == 1:
            return f(*args, **kwargs)
        else:
            return abort(404)
    return decorator_function

###########-------------HOME PAGE-------------#####################
@app.route("/")
@getData
def indexPage(**kwargs):
    content = {
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("home.html", **content)
###########-------------HOME PAGE-------------#####################


###########-------------REGISTER PAGE-------------#####################
@app.route("/rejestracja", methods=["POST", "GET"])
@login_required
@adminOnly
@getData
def register(**kwargs):
    alerts = []
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        confirmPassword = request.form["confirmPassword"]
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        user_2 = db.session.execute(db.select(User).where(User.username == username)).scalar()
        if user or user_2:
            alerts.append("Użytkownik nie istnieje!")
        elif password != confirmPassword:
            alerts.append("Hasło jest nieprawidłowe!")
        elif username == "" or email == "" or password == "":
            alerts.append("Puste miejsce!")
        elif "@" not in email:
            alerts.append("Email jest jest nieprawidłowy!")
        else:
            hashPassword = generate_password_hash(password, salt_length=9)
            new_user = User(username=username, email=email, password=hashPassword)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for("indexPage"))
    content = {
        "logged_in": current_user.is_authenticated,
        "alerts": alerts,
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("register.html", **content)
###########-------------REGISTER PAGE-------------#####################


###########-------------LOGIN PAGE-------------#####################
@app.route("/logowanie", methods=["POST", "GET"])
@getData
def login(**kwargs):
    alert = ""
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = db.session.execute(db.Select(User).where(User.email == email)).scalar()
        if email == "" or password == "":
            alert = "Puste pole!"
        elif not user:
            alert = "Użytkownik już istnieje!"
        elif check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("indexPage"))
        else:
            alert = "Błędne hasło!"
    content = {
        "logged_in": current_user.is_authenticated,
        "alert": alert,
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("login.html", **content)
###########-------------LOGIN PAGE-------------#####################


###########-------------LOGUT PAGE-------------#####################
@app.route("/wylogowanie")
@login_required
def logout():
    logout_user()
    return redirect(url_for("indexPage"))
###########-------------LOGUT PAGE-------------#####################


###########-------------ADD ITEM-------------#####################
@app.route("/dodajPrzedmiot", methods=["POST", "GET"])
@login_required
@adding
@getData
def addItem(**kwargs):
    alerts = []
    form = itemForm()
    form.category.choices = [(category.name, category.name) for category in db.session.execute(db.select(Category)).scalars().all()]
    form.store.choices = [(store.name, store.name) for store in db.session.execute(db.select(Store)).scalars().all()]
    if form.validate_on_submit():
        title = form.title.data
        author = form.author.data
        category = form.category.data
        store = form.store.data
        category = db.session.execute(db.select(Category).where(Category.name == category)).scalar()
        store = db.session.execute(db.select(Store).where(Store.name == store)).scalar()
        new_item = Item(title=title, author=author, category=category, store=store, status="noBorrow", user=current_user, data=datetime.now().strftime("%Y - %m - %d"))
        db.session.add(new_item)
        db.session.commit()
        alerts.append("Dodano pomyślnie!")
    content = {
        "logged_in": current_user.is_authenticated,
        "form": form,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "alerts": alerts,
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)
###########-------------ADD ITEM-------------#####################


###########-------------ADD CATEGORY-------------#####################
@app.route("/dodajKategorię", methods=["POST", "GET"])
@login_required
@adding
@getData
def addCategory(**kwargs):
    alerts = []
    form = categoriesForm()
    if form.validate_on_submit():
        name = form.name.data
        if db.session.execute(db.select(Category).where(Category.name == name)).scalar():
            alerts.append("Kategoria już istnieje!")
        else:
            new_category = Category(name=name, data=datetime.now().strftime("%Y - %m - %d"), user=current_user)
            db.session.add(new_category)
            db.session.commit()
            alerts.append("Dodano pomyślnie!")
    content = {
        "logged_in": current_user.is_authenticated,
        "form": form,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "alerts": alerts,
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)
###########-------------ADD CATEGORY-------------#####################


###########-------------ADD STORE-------------#####################
@app.route("/dodajMagazyn", methods=["POST", "GET"])
@login_required
@adding
@getData
def addStore(**kwargs):
    alerts = []
    form = storesForm()
    if form.validate_on_submit():
        name = form.name.data
        if db.session.execute(db.select(Store).where(Store.name == name)).scalar():
            alerts.append("Magazyn już istnieje!")
        else:
            new_store = Store(name=name, user=current_user)
            db.session.add(new_store)
            db.session.commit()
            alerts.append("Dodano pomyślnie!")
    content = {
        "logged_in": current_user.is_authenticated,
        "form": form,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "alerts": alerts,
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)
###########-------------ADD STORE-------------#####################


###########-------------GET ALL-------------#####################
@app.route("/wszystkiePrzedmioty")
@login_required
@reading
@getData
def getAll(**kwargs):
    content = {
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "items": db.session.execute(db.select(Item).where(Item.status != "deleted")).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("allitems.html", **content)
###########-------------GET ALL-------------#####################

###########-------------GET CATEGORY-------------#####################
@app.route("/kategoria-<int:num>")
@login_required
@reading
@getData
def getCategory(num, **kwargs):
    db.get_or_404(Category, num)
    content = {
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "items": db.session.execute(db.select(Item).where(Item.category_id == num, Item.status != "deleted")).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("allitems.html", **content)
###########-------------GET CATEGORY-------------#####################


###########-------------GET STORE-------------#####################

@app.route("/magazyn-<int:num>")
@login_required
@reading
@getData
def getStore(num, **kwargs):
    db.get_or_404(Store, num)
    content = {
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store).where()).scalars().all(),
        "items": db.session.execute(db.select(Item).where(Item.store_id == num, Item.status != "deleted")).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("allitems.html", **content)
###########-------------GET STORE-------------#####################



###########--------------GET DELETED ITEM-----###########################
@app.route("/usuniętePrzedmioty")
@login_required
@reading
@getData
def deletedItem(**kwargs):
    content = {
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store).where()).scalars().all(),
        "items": db.session.execute(db.select(Item).where(Item.status == "deleted")).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("deletedItems.html", **content)
###########--------------GET DELETED ITEM-----###########################


###########-------------GET OUTDATE-------------#####################
@app.route("/opóźnione")
@login_required
@reading
@getData
def getOutdated(**kwargs):
    borrows = db.session.execute(db.select(Borrow)).scalars().all()
    items = [borrow.item for borrow in borrows if datetime.strptime(borrow.to_date, "%Y-%m-%d").date() <= datetime.now().date()]
    content = {
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "items": items,
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("allitems.html", **content)
###########-------------GET OUTDATE-------------#####################


###########-------------ADD BORROW-------------#####################
@app.route("/wypożyczanie/<int:num>", methods=["POST", "GET"])
@editing
@getData
def borrow(num, **kwargs):
    item = db.get_or_404(Item, num)
    form = borrowForm(start_date=datetime.now().date())
    if db.session.execute(db.select(Borrow).where(Borrow.item_id == num)).scalar():
        return abort(404)
    if form.validate_on_submit():
        borrower = form.borrower.data
        to_date = form.finish_date.data
        start_date = datetime.now().strftime("%Y-%m-%d")
        user = current_user
        new_borrow = Borrow(item=item, borrower=borrower, to_date=to_date, start_date=start_date, user=user)
        item.status = "borrow"
        db.session.commit()
        db.session.add(new_borrow)
        db.session.commit()
        if item.category:
            return redirect(url_for("getCategory", num=item.category_id))
        else:
            return redirect(url_for("getAll"))
    content = {
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "form": form,
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)
###########-------------ADD BORROW-------------#####################


###########-------------EDIT ITEM-------------#####################
@app.route("/edytujPrzedmiot/<int:num>", methods=["GET", "POST"])
@login_required
@editing
@getData
def editItem(num, **kwargs):
    item = db.get_or_404(Item, num)
    if not item.category:
        category_form = False
    else:
        category_form = item.category.name
    if not item.store:
        store_form = False
    else:
        store_form = item.store.name
    if item.status == "borrow":
        for borrow in item.borrow:
            borrow = borrow
        form = itemFormForBorrow(title=item.title, author=item.author, borrower=borrow.borrower, category=category_form, store=store_form, finish_date=datetime.strptime(borrow.to_date, "%Y-%m-%d").date())
        form.category.choices = [(category.name, category.name) for category in db.session.execute(db.select(Category)).scalars().all()]
        form.store.choices = [(store.name, store.name) for store in db.session.execute(db.select(Store)).scalars().all()]
    else:
        form = itemForm(title=item.title, author=item.author, category=category_form, store=store_form)
        form.category.choices = [(category.name, category.name) for category in db.session.execute(db.select(Category)).scalars().all()]
        form.store.choices = [(store.name, store.name) for store in db.session.execute(db.select(Store)).scalars().all()]
    if form.validate_on_submit():
        title = form.title.data
        author = form.author.data
        category = form.category.data
        store = form.store.data
        category = db.session.execute(db.select(Category).where(Category.name == category)).scalar()
        store = db.session.execute(db.select(Store).where(Store.name == store)).scalar()
        item.title = title
        item.author = author
        item.category = category
        item.store = store
        item.category = category
        if item.status == "borrow":
            borrow.to_date = form.finish_date.data
        db.session.commit()
        if item.category:
            return redirect(url_for("getCategory", num=item.category_id))
        else:
            return redirect(url_for("getAll"))
    content = {
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "form": form,
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)
###########-------------EDIT ITEM-------------#####################



###########-------------DELETE BORROW-------------#####################

@app.route("/oddaj/<int:num>", methods=["POST", "GET"])
@login_required
@editing
@confirmPassword
def deleteBorrow(num):
    item = db.get_or_404(Item, num)
    for borrow in item.borrow:
        borrow = borrow
    db.session.delete(borrow)
    item.status = "noBorrow"
    db.session.commit()
    if item.category:
        return redirect(url_for("getCategory", num=item.category_id))
    else:
        return redirect(url_for("getAll"))
###########-------------DELETE BORROW-------------#####################


###########-------------DELETE ITEM-------------#####################
@app.route("/usunPrzedmiot/<int:num>", methods=["POST", "GET"])
@login_required
@deleting
@confirmPassword
def deleteItem(num):
    item = db.get_or_404(Item, num)
    if item.borrow:
        return abort(404)
    item.status = "deleted"
    db.session.commit()
    if item.category:
        return redirect(url_for("getCategory", num=item.category_id))
    else:
        return redirect(url_for("getAll"))
###########-------------DELETE ITEM-------------#####################



###########-------------DELETE CATEGORY-------------#####################
@app.route("/usunKategorie", methods=["GET", "POST"])
@login_required
@deleting
@getData
def deleteCategory(**kwargs):
    alerts = []
    form = selectCategoryForm()
    form.categories.choices = [(category.name, category.name) for category in db.session.execute(db.select(Category)).scalars().all()]
    if form.validate_on_submit():
        category_name = form.categories.data
        category = db.session.execute(db.select(Category).where(Category.name == category_name)).scalar()
        items = db.session.execute(db.select(Item).where(Item.status != "deleted", Item.category_id == category.id)).scalars().all()
        if not items:
            db.session.delete(category)
            db.session.commit()
            return redirect(request.referrer)
        else:
            alerts.append("Musisz zmienić kategorię w przedmiotach, które mają kategorię, którą chcesz usunąć!")
    content = {
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "form": form,
        "alerts": alerts,
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)
###########-------------DELETE CATEGORY-------------#####################

###########-------------DELETE STORE-------------#####################
@app.route("/usunMagazyn", methods=["GET", "POST"])
@login_required
@deleting
@getData
def deleteStore(**kwargs):
    alerts = []
    form = selectStoreForm()
    form.stores.choices = [(store.name, store.name) for store in db.session.execute(db.select(Store)).scalars().all()]
    if form.validate_on_submit():
        store_name = form.stores.data
        store = db.session.execute(db.select(Store).where(Store.name == store_name)).scalar()
        items = db.session.execute(db.select(Item).where(Item.store_id == store.id, Item.status != "deleted")).scalars().all()
        if not items:
            db.session.delete(store)
            db.session.commit()
            return redirect(request.referrer)
        else:
            alerts.append("Musisz zmienić magazyn w przedmiotach, które mają magazyn, który chcesz usunąć!")
    content = {
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "form": form,
        "alerts": alerts,
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)
###########-------------DELETE STORE-------------#####################


###########-------------ADD PERMISSION TO USER-------------#####################
@app.route("/zmienPermisjeDlaUzytkownika/<int:num>", methods=["POST", "GET"])
@adminOnly
@getData
def changePermission(num, **kwargs):
    alerts = []
    user = db.get_or_404(User, num)
    form = addPermissionToUserForm(reading_child="czytanie dzieci" in [permission.name for permission in user.permissions],
                                   editing_child="edycja dzieci" in [permission.name for permission in user.permissions],
                                   adding_child="dodawanie dzieci" in [permission.name for permission in user.permissions],
                                   deleting_child="usuwanie dzieci" in [permission.name for permission in user.permissions],
                                   reading_item="czytanie przedmioty" in [permission.name for permission in user.permissions],
                                   editing_item="edycja przedmioty" in [permission.name for permission in user.permissions],
                                   adding_item="dodawanie przedmioty" in [permission.name for permission in user.permissions],
                                   deleting_item="usuwanie przedmioty" in [permission.name for permission in user.permissions])
    if form.validate_on_submit():
        permission = db.session.execute(db.select(Permission).where(Permission.name == "czytanie przedmioty")).scalar()
        if "czytanie przedmioty" not in [permission.name for permission in user.permissions] and form.reading_item.data:
            user.permissions.append(permission)
        elif "czytanie przedmioty" in [permission.name for permission in user.permissions] and not form.reading_item.data:
            user.permissions.remove(permission)

        permission = db.session.execute(db.select(Permission).where(Permission.name == "dodawanie przedmioty")).scalar()
        if "dodawanie przedmioty" not in [permission.name for permission in user.permissions] and form.adding_item.data:
            user.permissions.append(permission)
        elif "dodawanie przedmioty" in [permission.name for permission in user.permissions] and not form.adding_item.data:
            user.permissions.remove(permission)

        permission = db.session.execute(db.select(Permission).where(Permission.name == "edycja przedmioty")).scalar()
        if "edycja przedmioty" not in [permission.name for permission in user.permissions] and form.editing_item.data:
            user.permissions.append(permission)
        elif "edycja przedmioty" in [permission.name for permission in user.permissions] and not form.editing_item.data:
            user.permissions.remove(permission)

        permission = db.session.execute(db.select(Permission).where(Permission.name == "usuwanie przedmioty")).scalar()
        if "usuwanie przedmioty" not in [permission.name for permission in user.permissions] and form.deleting_item.data:
            user.permissions.append(permission)
        elif "usuwanie przedmioty" in [permission.name for permission in user.permissions] and not form.deleting_item.data:
            user.permissions.remove(permission)



        permission = db.session.execute(db.select(Permission).where(Permission.name == "czytanie dzieci")).scalar()
        if "czytanie dzieci" not in [permission.name for permission in user.permissions] and form.reading_child.data:
            user.permissions.append(permission)
        elif "czytanie dzieci" in [permission.name for permission in user.permissions] and not form.reading_child.data:
            user.permissions.remove(permission)

        permission = db.session.execute(db.select(Permission).where(Permission.name == "dodawanie dzieci")).scalar()
        if "dodawanie dzieci" not in [permission.name for permission in user.permissions] and form.adding_child.data:
            user.permissions.append(permission)
        elif "dodawanie dzieci" in [permission.name for permission in user.permissions] and not form.adding_child.data:
            user.permissions.remove(permission)

        permission = db.session.execute(db.select(Permission).where(Permission.name == "edycja dzieci")).scalar()
        if "edycja dzieci" not in [permission.name for permission in user.permissions] and form.editing_child.data:
            user.permissions.append(permission)
        elif "edycja dzieci" in [permission.name for permission in user.permissions] and not form.editing_child.data:
            user.permissions.remove(permission)

        permission = db.session.execute(db.select(Permission).where(Permission.name == "usuwanie dzieci")).scalar()
        if "usuwanie dzieci" not in [permission.name for permission in user.permissions] and form.deleting_child.data:
            user.permissions.append(permission)
        elif "usuwanie dzieci" in [permission.name for permission in user.permissions] and not form.deleting_child.data:
            user.permissions.remove(permission)
        db.session.commit()
        return redirect(url_for("allUsers"))
    content = {
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "form": form,
        "alerts": alerts,
        "all_permissions": kwargs["all_permissions"],
        "user": user
    }
    return render_template("changepermission.html", **content)
###########-------------ADD PERMISSION TO USER-------------#####################


###########------------- GET ALL USERS -------------#####################
@app.route("/wszyscyUżytkownicy")
@login_required
@adminOnly
@getData
def allUsers(**kwargs):
    users = db.session.execute(db.select(User)).scalars().all()
    content = {
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "users": users,
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("allusers.html", **content)
###########------------- GET ALL USERS -------------#####################

###########------------- GET ALL CHILDREN -------------#####################
@app.route("/wszystkieDzieci")
@login_required
@reading_dzieci
@getData
def getAllChildren(**kwargs):
    session['URL'] = request.url
    filters = check_filter(session['URL'])
    children = db.session.execute(db.select(Child)).scalars().all()
    kid = None
    if request.args.get("dziecko"):
        kid = int(request.args.get("dziecko"))
    if kid:
        children = [child for child in children if child.id == kid]
    start_date = request.args.get("od")
    end_date = request.args.get("do")

    if start_date:
        new_children = []
        for child in children:
            x = False
            for activity in child.activities:
                if activity.end_date:
                    if activity.end_date.date() >= datetime.strptime(start_date, "%Y-%m-%d").date():
                        x = True
                        break
                elif activity.start_date.date() >= datetime.strptime(start_date, "%Y-%m-%d").date():
                    x = True
                    break
            if x:
                new_children.append(child)
        children = new_children

    if end_date:
        new_children = []
        for child in children:
            x = False
            for activity in child.activities:
                if activity.start_date.date() <= datetime.strptime(end_date, "%Y-%m-%d").date():
                    x = True
                    break
            if x:
                new_children.append(child)
        children = new_children

    late = request.args.get("opóźnione")

    if late:
        new_children = []
        if late == "wszystko":
            for child in children:
                if not child.expiration_dates or not child.agreements or not child.IPET or not child.wofus:
                    continue
                elif child.expiration_dates[-1].date.date() < datetime.now().date() or child.agreements[-1].date.date() < datetime.now().date() or child.IPET < datetime.now().date() or child.wofus[-1].date.date() < datetime.now().date():
                    new_children.append(child)

                children = new_children
        if late == "orzeczenie":
            for child in children:
                if not child.expiration_dates:
                    continue
                elif child.expiration_dates[-1].date.date() < datetime.now().date():
                    new_children.append(child)

                children = new_children
        if late == "umowa":
            for child in children:
                if not child.agreements:
                    continue
                elif child.agreements[-1].date.date() < datetime.now().date():
                    new_children.append(child)

                children = new_children
        if late == "ipet":
            for child in children:
                if not child.IPET:
                    continue
                elif child.IPET < datetime.now().date():
                    new_children.append(child)

                children = new_children
        if late == "wofu":
            for child in children:
                if not child.wofus:
                    continue
                elif child.wofus[-1].date.date() < datetime.now().date():
                    new_children.append(child)

        children = new_children

    miss = request.args.get("braki")

    if miss:
        new_children = []
        if miss == "wszystko":
            for child in children:
                if not child.expiration_dates or not child.agreements or not child.IPET or not child.wofus or not child.managements or not child.teachers or not child.therapies:
                    new_children.append(child)
                else:
                    new_children = []
                    for child in children:
                        x = False
                        for activity in child.activities:
                            if not activity.card:
                                x = True
                        if x:
                            new_children.append(child)
                children = new_children
        if miss == "orzeczenie":
            for child in children:
                if not child.expiration_dates:
                    new_children.append(child)

                children = new_children
        if miss == "terapeuta":
            for child in children:
                if not child.teachers:
                    new_children.append(child)
                children = new_children

        if miss == "terapia":
            for child in children:
                if not child.therapies:
                    new_children.append(child)
                children = new_children
        if miss == "umowa":
            for child in children:
                if not child.agreements:
                    new_children.append(child)

                children = new_children
        if miss == "ipet":
            for child in children:
                if not child.IPET:
                    new_children.append(child)

                children = new_children
        if miss == "zarządzenie":
            for child in children:
                if not child.managements:
                    new_children.append(child)

                children = new_children
        if miss == "wofu":
            for child in children:
                if not child.wofus:
                    new_children.append(child)

                children = new_children

        if miss == "kartazgłoszeń":
            new_children = []
            for child in children:
                x = False
                for activity in child.activities:
                    if not activity.card:
                        x = True
                if x:
                    new_children.append(child)
            children = new_children

    typeOfTherapy = request.args.get("terapia")

    if typeOfTherapy:
        therapy = db.session.execute(db.select(Therapy).where(Therapy.name == typeOfTherapy)).scalar()
        children = [child for child in children if therapy in child.therapies]

    teacher = request.args.get("terapeuta")

    if teacher:
        teacher = db.session.execute(db.select(Teacher).where(Teacher.name == teacher)).scalar()
        children = [child for child in children if teacher in child.teachers]


    content = {
        "children": children,
        "filters": filters,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"],
        "len": my_len
    }
    return render_template("childreen.html", **content)
###########------------- GET ALL CHILDREN -------------#####################

@app.route("/usuńFiltr")
def deleteFilter():
    url = remove_last_param(session["URL"])
    return redirect(url)


@app.route("/wprowadźDziecko", methods=["POST", "GET"])
@reading_dzieci
@adding_child
@getData
def inputChild(**kwargs):
    form = inputChildrenForm()

    if form.validate_on_submit():
        name = form.name.data
        birth = form.birth.data

        child = Child(name=name, birth=birth)

        db.session.add(child)
        db.session.commit()
        return redirect(session['URL'])

    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)



###########------------- DELETE USER -------------#####################
@app.route("/deleteUser/<int:num>", methods=["POST", "GET"])
@adminOnly
@confirmPassword
def deleteUser(num):
    user = db.get_or_404(User, num)
    if user.id != 1:
        db.session.delete(user)
        db.session.commit()
        return redirect(url_for("allUsers"))
    else:
        return abort(404)
###########------------- DELETE USER -------------#####################

###########------------- DOWNLOAD ITEM TO CSV -------------#####################
@app.route("/download_all")
@login_required
@reading
def downloadAll():
    items = db.session.execute(db.select(Item)).scalars().all()
    if items:
        titles = [item.title for item in items]
        authors = [item.author for item in items]
        categories = [item.category.name for item in items]
        stores = [item.store.name for item in items]

        date = pd.DataFrame({"tytuł": titles, "autor/wydawnictwo": authors, "kategoria": categories, "magazyn": stores})

        date.to_csv("przedmioty.csv", index=False)
        return send_file("przedmioty.csv", as_attachment=True)
    else:
        return abort(404)
###########------------- DOWNLOAD ITEM TO CSV -------------#####################


###########------------- RETURN ITEM  -------------#####################
@app.route("/zwróćPrzedmiot/<int:num>")
@login_required
@editing
def returnItem(num):
    item = db.get_or_404(Item, num)
    item.status = "noBorrow"
    db.session.commit()
    return redirect(request.referrer)
###########------------- RETURN ITEM  -------------#####################


###########------------- DELETE ITEM  -------------#####################
@app.route("/deleteItem/<int:num>", methods=["POST", "GET"])
@login_required
@adminOnly
@confirmPassword
def deleteItemForever(num):
    item = db.get_or_404(Item, num)
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for("deletedItem"))
###########------------- DELETE ITEM  -------------#####################


###########------------- ADD EXPIRATION  -------------#####################
@app.route("/dodajOrzeczenie/<int:num>", methods=["POST", "GET"])
@login_required
@reading_dzieci
@adding_child
@getData
def addExpiration(num, **kwargs):
    child = db.get_or_404(Child, num)
    form = dateForm()
    if form.validate_on_submit():
        expiration_date = ExpirationDate(name=form.name.data, date=form.date.data, child=child)
        db.session.add(expiration_date)
        db.session.commit()
        return redirect(session['URL'])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)
###########------------- ADD EXPIRATION  -------------#####################

###########------------- ADD AGREEMENT  -------------#####################
@app.route("/dodajUmowę/<int:num>", methods=["POST", "GET"])
@login_required
@reading_dzieci
@adding_child
@getData
def addAgreement(num, **kwargs):
    child = db.get_or_404(Child, num)
    form = dateForm()
    if form.validate_on_submit():
        agreement = Agreement(name=form.name.data, date=form.date.data, child=child)
        db.session.add(agreement)
        db.session.commit()
        return redirect(session['URL'])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)
###########------------- ADD AGREEMENT  -------------#####################

###########------------- ADD ACTIVITY  -------------#####################
@app.route("/dodajOpiekę/<int:num>", methods=["POST", "GET"])
@login_required
@reading_dzieci
@adding_child
@getData
def addActivity(num, **kwargs):
    child = db.get_or_404(Child, num)
    form = addAcitivityForm()
    if form.validate_on_submit():
        activity = Activity(name=form.name.data, start_date=form.start_date.data, child=child)
        db.session.add(activity)
        db.session.commit()
        return redirect(session['URL'])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)
###########------------- ADD ACTIVITY  -------------#####################

###########------------- ADD WOFU -------------#####################
@app.route("/dodajWofu/<int:num>", methods=["POST", "GET"])
@login_required
@reading_dzieci
@adding_child
@getData
def addWofu(num, **kwargs):
    child = db.get_or_404(Child, num)
    form = dateForm()
    if form.validate_on_submit():
        wofu = WOFU(name=form.name.data, date=form.date.data, child=child)
        db.session.add(wofu)
        db.session.commit()
        return redirect(session['URL'])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }

    return render_template("addItem.html", **content)
###########------------- ADD WOFU -------------#####################

###########------------- ADD MANAGEMENT -------------#####################
@app.route("/dodajZarządzenie/<int:num>", methods=["POST", "GET"])
@login_required
@reading_dzieci
@adding_child
@getData
def addManagement(num, **kwargs):
    child = db.get_or_404(Child, num)
    form = managementForm()
    if form.validate_on_submit():
        management = Management(name=form.name.data, child=child)
        db.session.add(management)
        db.session.commit()
        return redirect(session['URL'])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }

    return render_template("addItem.html", **content)
###########------------- ADD MANAGEMENT -------------#####################

###########------------- DELETE MANAGEMENT -------------#####################
@app.route("/usuńZarządzenie/<int:num>", methods=["POST", "GET"])
@login_required
@reading_dzieci
@deleting_child
@getData
def deleteManagement(num, **kwargs):
    child = db.get_or_404(Child, num)
    form = selectForm()
    if child.expiration_dates:
        form.name.choices = [(management.id, management.name) for management in child.managements]
    if form.validate_on_submit():
        management_id = form.name.data
        management = db.get_or_404(Management, management_id)
        db.session.delete(management)
        db.session.commit()
        return redirect(session['URL'])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)
###########------------- DELETE MANAGEMENT -------------#####################


###########------------- DELETE EXPIRATION -------------#####################
@app.route("/usuńOrzeczenie/<int:num>", methods=["POST", "GET"])
@login_required
@reading_dzieci
@deleting_child
@getData
def deleteExpiration(num, **kwargs):
    child = db.get_or_404(Child, num)
    form = selectForm()
    if child.expiration_dates:
        form.name.choices = [(expiration.id, f"{expiration.date.strftime('%Y - %m - %d')} {expiration.name}") for expiration in child.expiration_dates]
    if form.validate_on_submit():
        expiration_id = form.name.data
        expiration = db.get_or_404(ExpirationDate, expiration_id)
        db.session.delete(expiration)
        db.session.commit()
        return redirect(session['URL'])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)
###########------------- DELETE EXPIRATION -------------#####################

###########------------- DELETE AGREEMENT -------------#####################
@app.route("/usuńUmowę/<int:num>", methods=["POST", "GET"])
@login_required
@reading_dzieci
@deleting_child
@getData
def deleteAgreement(num, **kwargs):
    child = db.get_or_404(Child, num)
    form = selectForm()
    if child.agreements:
        form.name.choices = [(agreement.id, f"{agreement.date.strftime('%Y - %m - %d')} {agreement.name}") for agreement in child.agreements]
    if form.validate_on_submit():
        agreement_id = form.name.data
        agreement = db.get_or_404(Agreement, agreement_id)
        db.session.delete(agreement)
        db.session.commit()
        return redirect(session['URL'])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)
###########------------- DELETE AGREEMENT -------------#####################

###########------------- DELETE ACTIVITY -------------#####################
@app.route("/usuńOpiekę/<int:num>", methods=["POST", "GET"])
@login_required
@reading_dzieci
@deleting_child
@getData
def deleteActivity(num, **kwargs):
    child = db.get_or_404(Child, num)
    form = selectForm()
    if child.activities:
        form.name.choices = [(activity.id, f"Od {activity.start_date.strftime('%Y - %m - %d')} {activity.name}") for activity in child.activities]
    if form.validate_on_submit():
        activity_id = form.name.data
        activity = db.get_or_404(Activity, activity_id)
        db.session.delete(activity)
        db.session.commit()
        return redirect(session['URL'])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)
###########------------- DELETE ACTIVITY -------------#####################

###########------------- DELETE IPET -------------#####################
@app.route("/usuńIPET/<int:num>")
@login_required
@reading_dzieci
@deleting_child
def deleteIPET(num):
    child = db.get_or_404(Child, num)
    child.IPET = None
    db.session.commit()
    return redirect(request.referrer)
###########------------- DELETE IPET -------------#####################

###########------------- DELETE WOFU -------------#####################
@app.route("/usuńWofu/<int:num>", methods=["POST", "GET"])
@login_required
@reading_dzieci
@deleting_child
@getData
def deleteWofu(num, **kwargs):
    child = db.get_or_404(Child, num)
    form = selectForm()
    if child.wofus:
        form.name.choices = [(wofu.id, f"{wofu.date.strftime('%Y - %m - %d')} {wofu.name}") for wofu in child.wofus]
    if form.validate_on_submit():
        wofu_id = form.name.data
        wofu = db.get_or_404(WOFU, wofu_id)
        db.session.delete(wofu)
        db.session.commit()
        return redirect(session['URL'])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)
###########------------- DELETE WOFU -------------#####################

###########------------- CHANGE COPY -------------#####################
@app.route("/kopiaOrzeczenia/<int:num>", methods=["POST", "GET"])
@login_required
@reading_dzieci
@adding_child
@getData
def addCopy(num, **kwargs):
    child = db.get_or_404(Child, num)
    form = selectForm()
    if child.expiration_dates:
        form.name.choices = [(expiration.id, f"{expiration.date.strftime('%Y - %m - %d')} {expiration.name}") for expiration in child.expiration_dates if not expiration.copy]
    if form.validate_on_submit():
        expiration_id = form.name.data
        expiration = db.get_or_404(ExpirationDate, expiration_id)
        expiration.copy = True
        db.session.commit()
        return redirect(session['URL'])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)

@app.route("/addCard/<int:num>", methods=["POST", "GET"])
@login_required
@reading_dzieci
@adding_child
@getData
def addCard(num, **kwargs):
    child = db.get_or_404(Child, num)
    form = selectForm()
    if child.activities:
        form.name.choices = [(activity.id, f"{activity.start_date.strftime('%Y - %m - %d')} {activity.name}") for activity in child.activities if not activity.card]
    if form.validate_on_submit():
        activity_id = form.name.data
        activity = db.get_or_404(Activity, activity_id)
        activity.card = True
        db.session.commit()
        return redirect(session['URL'])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)


@app.route("/deleteCard/<int:num>", methods=["POST", "GET"])
@login_required
@reading_dzieci
@adding_child
@getData
def deleteCard(num, **kwargs):
    child = db.get_or_404(Child, num)
    form = selectForm()
    if child.activities:
        form.name.choices = [(activity.id, f"{activity.start_date.strftime('%Y - %m - %d')} {activity.name}") for activity in child.activities if activity.card]
    if form.validate_on_submit():
        activity_id = form.name.data
        activity = db.get_or_404(Activity, activity_id)
        activity.card = False
        db.session.commit()
        return redirect(session['URL'])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)


@app.route("/usuńKopię/<int:num>", methods=["POST", "GET"])
@login_required
@reading_dzieci
@deleting_child
@getData
def deleteCopy(num, **kwargs):
    child = db.get_or_404(Child, num)
    form = selectForm()
    if child.expiration_dates:
        form.name.choices = [(expiration.id, f"{expiration.date.strftime('%Y - %m - %d')} {expiration.name}") for expiration in child.expiration_dates if expiration.copy]
    if form.validate_on_submit():
        expiration_id = form.name.data
        expiration = db.get_or_404(ExpirationDate, expiration_id)
        expiration.copy = False
        db.session.commit()
        return redirect(session['URL'])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)
###########------------- CHANGE COPY -------------#####################



@app.route("/usuńDziecko", methods=["POST", "GET"])
@login_required
@reading_dzieci
@deleting_child
@getData
def deleteChild(**kwargs):
    form = selectForm()
    children = db.session.execute(db.select(Child)).scalars().all()
    form.name.choices = [(child.id, child.name) for child in children]
    if form.validate_on_submit():
        child_id = form.name.data
        child = db.get_or_404(Child, child_id)
        db.session.delete(child)
        db.session.commit()
        return redirect(session['URL'])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)


###########------------- END ACTIVITY -------------#####################
@app.route("/zakończOpiekę/<int:num>", methods=["POST", "GET"])
@login_required
@reading_dzieci
@editing_child
@getData
def endActivity(num, **kwargs):
    activity = db.get_or_404(Activity, num)
    form = endAcitivityForm()
    if form.validate_on_submit():
        activity.end_date = form.end_date.data
        db.session.commit()
        return redirect(session['URL'])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)
###########------------- END ACTIVITY -------------#####################

###########------------- INPUT IPET -------------#####################
@app.route("/wprowadźIPET/<int:num>", methods=["POST", "GET"])
@login_required
@reading_dzieci
@adding_child
@getData
def inputIPET(num, **kwargs):
    child = db.get_or_404(Child, num)
    if child.IPET:
        form = ipetForm(date=child.IPET)
    else:
        form = ipetForm()
    if form.validate_on_submit():
        child.IPET = form.date.data
        db.session.commit()
        return redirect(session['URL'])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)
###########------------- INPUT IPET -------------#####################


###########------------- INPUT IPET -------------#####################
@app.route("/segregacjaWgDaty", methods=["POST", "GET"])
@login_required
@reading_dzieci
@getData
def dateSegregator(**kwargs):
    form = dateSegregatorForm()
    if form.validate_on_submit():
        start_date = form.start_date.data
        end_date = form.end_date.data

        url = add_or_update_param(session["URL"], "od", start_date)
        url = add_or_update_param(url, "do", end_date)

        return redirect(url)
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)

@app.route("/segregacjaWgTerapii", methods=["POST", "GET"])
@login_required
@reading_dzieci
@getData
def therapySegregator(**kwargs):
    form = selectForm()
    form.name.choices = [(therapy.name, therapy.name) for therapy in
                         db.session.execute(db.select(Therapy)).scalars().all()]
    if form.validate_on_submit():
        url = add_or_update_param(session["URL"], "terapia", form.name.data)

        return redirect(url)
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)


@app.route("/segregacjaWgTerapeuty", methods=["POST", "GET"])
@login_required
@reading_dzieci
@getData
def teacherSegregator(**kwargs):
    form = selectForm()
    form.name.choices = [(teacher.name, teacher.name) for teacher in
                         db.session.execute(db.select(Teacher)).scalars().all()]
    if form.validate_on_submit():
        url = add_or_update_param(session["URL"], "terapeuta", form.name.data)

        return redirect(url)
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)

@app.route("/segregacjaSpoznione", methods=["POST", "GET"])
@login_required
@reading_dzieci
@getData
def lateSegregator(**kwargs):
    form = lateSegregatorForm()
    if form.validate_on_submit():
        x = form.late.data

        url = add_or_update_param(session["URL"], "opóźnione", x)

        return redirect(url)
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)


@app.route("/segregacjaBraki", methods=["POST", "GET"])
@login_required
@reading_dzieci
@getData
def missSegregator(**kwargs):
    form = missSegregatorForm()
    if form.validate_on_submit():
        x = form.miss.data

        url = add_or_update_param(session["URL"], "braki", x)

        return redirect(url)
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)


@app.route("/dodawanieTerapii", methods=["POST", "GET"])
@login_required
@adding_child
@getData
def addingTherapy(**kwargs):
    form = therapyForm()
    if form.validate_on_submit():
        name = form.name.data
        therapy = Therapy(name=name)
        db.session.add(therapy)
        db.session.commit()
        return redirect(session["URL"])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)

@app.route("/dodawanieTerapeuty", methods=["POST", "GET"])
@login_required
@adding_child
@getData
def addingTeacher(**kwargs):
    form = teacherForm()
    if form.validate_on_submit():
        name = form.name.data
        teacher = Teacher(name=name)
        db.session.add(teacher)
        db.session.commit()
        return redirect(session["URL"])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)


@app.route("/dodajTerapięDoDziecka/<int:num>", methods=["POST", "GET"])
@login_required
@editing_child
@getData
def addingTherapyToChild(num, **kwargs):
    form = selectForm()
    child = db.get_or_404(Child, num)
    form.name.choices = [(therapy.id, therapy.name) for therapy in db.session.execute(db.select(Therapy)).scalars() if therapy not in child.therapies]
    if form.validate_on_submit():
        therapy = db.get_or_404(Therapy, form.name.data)
        child.therapies.append(therapy)
        db.session.commit()
        return redirect(session["URL"])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)


@app.route("/usuńTerapięDoDziecka/<int:num>", methods=["POST", "GET"])
@login_required
@editing_child
@getData
def deletingTherapyToChild(num, **kwargs):
    form = selectForm()
    child = db.get_or_404(Child, num)
    form.name.choices = [(therapy.id, therapy.name) for therapy in child.therapies]
    if form.validate_on_submit():
        therapy = db.get_or_404(Therapy, form.name.data)
        child.therapies.remove(therapy)
        db.session.commit()
        return redirect(session["URL"])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)

@app.route("/dodajTerapeutęDoDziecka/<int:num>", methods=["POST", "GET"])
@login_required
@editing_child
@getData
def addingTeacherToChild(num, **kwargs):
    form = selectForm()
    child = db.get_or_404(Child, num)
    form.name.choices = [(teacher.id, teacher.name) for teacher in db.session.execute(db.select(Teacher)).scalars() if teacher not in child.teachers]
    if form.validate_on_submit():
        teacher = db.get_or_404(Teacher, form.name.data)
        child.teachers.append(teacher)
        db.session.commit()
        return redirect(session["URL"])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)


@app.route("/usuńTerapeutęDoDziecka/<int:num>", methods=["POST", "GET"])
@login_required
@editing_child
@getData
def deletingTeacherToChild(num, **kwargs):
    form = selectForm()
    child = db.get_or_404(Child, num)
    form.name.choices = [(teacher.id, teacher.name) for teacher in child.teachers]
    if form.validate_on_submit():
        teacher = db.get_or_404(Teacher, form.name.data)
        child.teachers.remove(teacher)
        db.session.commit()
        return redirect(session["URL"])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)

@app.route("/usuńTerapię", methods=["POST", "GET"])
@login_required
@deleting_child
@getData
def deletingTherapy(**kwargs):
    form = selectForm()
    therapies = db.session.execute(db.select(Therapy)).scalars().all()
    form.name.choices = [(therapy.id, therapy.name) for therapy in therapies]
    if form.validate_on_submit():
        therapy = db.get_or_404(Therapy, form.name.data)
        db.session.delete(therapy)
        db.session.commit()
        return redirect(session["URL"])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)


@app.route("/usuńTerapeutę", methods=["POST", "GET"])
@login_required
@deleting_child
@getData
def deletingTeacher(**kwargs):
    form = selectForm()
    teachers = db.session.execute(db.select(Teacher)).scalars().all()
    form.name.choices = [(teacher.id, teacher.name) for teacher in teachers]
    if form.validate_on_submit():
        teacher = db.get_or_404(Teacher, form.name.data)
        db.session.delete(teacher)
        db.session.commit()
        return redirect(session["URL"])
    content = {
        "form": form,
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "all_permissions": kwargs["all_permissions"]
    }
    return render_template("addItem.html", **content)

if __name__  == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(3000))
