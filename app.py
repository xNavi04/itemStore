import werkzeug.security
from flask import Flask, render_template, request, redirect, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash
from flask_ckeditor import CKEditor
from flask_bootstrap import Bootstrap5
from forms import categoriesForm, storesForm, borrowForm, itemForm, itemFormForBorrow, selectCategoryForm, selectStoreForm, confirmReturnForm
from datetime import datetime
from functools import wraps
import os



app = Flask(__name__)
app.config["SECRET_KEY"] = "asdf89sdahvfad0vuhnadjiwsbjwe"
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://aaddcjlh:aKSlu6HHzRP5gcpYC8tXU-WvCIDgjVOt@horton.db.elephantsql.com/aaddcjlh"

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

with app.app_context():
    db.create_all()
    if not db.session.execute(db.select(User)).scalar():
        password = werkzeug.security.generate_password_hash("Admin1230")
        admin = User(username="Admin", email="m.religa@wp.pl", password=password)
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


###########-------------HOME PAGE-------------#####################
@app.route("/")
def indexPage():
    content = {
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all()
    }
    return render_template("home.html", **content)
###########-------------HOME PAGE-------------#####################


###########-------------REGISTER PAGE-------------#####################
@app.route("/rejestracja", methods=["POST", "GET"])
@login_required
@adminOnly
def register():
    alerts = []
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        confirmPassword = request.form["confirmPassword"]
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        user_2 = db.session.execute(db.select(User).where(User.username == username)).scalar()
        if user or user_2:
            alerts.append("This user is already exist!")
        elif password != confirmPassword:
            alerts.append("Password do not match!")
        elif username == "" or email == "" or password == "":
            alerts.append("Something is empty!")
        elif not "@" in email:
            alerts.append("Email is wrong!")
        else:
            hashPassword = generate_password_hash(password, salt_length=8)
            new_user = User(username=username, email=email, password=hashPassword)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("indexPage"))
    content = {
        "logged_in": current_user.is_authenticated,
        "alerts": alerts,
    }
    return render_template("register.html", **content)
###########-------------REGISTER PAGE-------------#####################


###########-------------LOGIN PAGE-------------#####################
@app.route("/logowanie", methods=["POST", "GET"])
def login():
    alert = ""
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = db.session.execute(db.Select(User).where(User.email == email)).scalar()
        if email == "" or password == "":
            alert = "Something is empty!"
        elif not user:
            alert = "This user is not exist!"
        elif check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("indexPage"))
        else:
            alert = "Wrong password"
    content = {
        "logged_in": current_user.is_authenticated,
        "alert": alert,
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
def addItem():
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
        "alerts": alerts
    }
    return render_template("addItem.html", **content)
###########-------------ADD ITEM-------------#####################


###########-------------ADD CATEGORY-------------#####################
@app.route("/dodajKategorię", methods=["POST", "GET"])
@login_required
def addCategory():
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
        "alerts": alerts
    }
    return render_template("addItem.html", **content)
###########-------------ADD CATEGORY-------------#####################


###########-------------ADD STORE-------------#####################
@app.route("/dodajMagazyn", methods=["POST", "GET"])
@login_required
def addStore():
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
            alerts = alerts.append("Dodano pomyślnie!")
    content = {
        "logged_in": current_user.is_authenticated,
        "form": form,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "alerts": alerts
    }
    return render_template("addItem.html", **content)
###########-------------ADD STORE-------------#####################


###########-------------GET ALL-------------#####################
@app.route("/wszystkiePrzedmioty")
@login_required
def getAll():
    content = {
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "items": db.session.execute(db.select(Item).where(Item.status != "deleted")).scalars().all()
    }
    return render_template("allitems.html", **content)
###########-------------GET ALL-------------#####################

###########-------------GET CATEGORY-------------#####################
@app.route("/kategoria-<int:num>")
@login_required
def getCategory(num):
    db.get_or_404(Category, num)
    content = {
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "items": db.session.execute(db.select(Item).where(Item.category_id == num, Item.status != "deleted")).scalars().all()
    }
    return render_template("allitems.html", **content)
###########-------------GET CATEGORY-------------#####################


###########-------------GET STORE-------------#####################

@app.route("/magazyn-<int:num>")
@login_required
def getStore(num):
    db.get_or_404(Store, num)
    content = {
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store).where()).scalars().all(),
        "items": db.session.execute(db.select(Item).where(Item.store_id == num, Item.status != "deleted")).scalars().all()
    }
    return render_template("allitems.html", **content)
###########-------------GET STORE-------------#####################



###########--------------GET DELETED ITEM-----###########################
@app.route("/usuniętePrzedmioty")
@login_required
def deletedItem():
    content = {
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store).where()).scalars().all(),
        "items": db.session.execute(db.select(Item).where(Item.status == "deleted")).scalars().all()
    }
    return render_template("deletedItems.html", **content)
###########--------------GET DELETED ITEM-----###########################






###########-------------GET OUTDATE-------------#####################
@app.route("/opóźnione")
@login_required
def getOutdated():
    borrows = db.session.execute(db.select(Borrow)).scalars().all()
    items = [borrow.item for borrow in borrows if datetime.strptime(borrow.to_date, "%Y-%m-%d").date() <= datetime.now().date()]
    content = {
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "items": items
    }
    return render_template("allitems.html", **content)
###########-------------GET OUTDATE-------------#####################


###########-------------ADD BORROW-------------#####################
@login_required
@app.route("/wypożyczanie/<int:num>", methods=["POST", "GET"])
def borrow(num):
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
        return redirect(url_for("getCategory", num=item.category_id))
    content = {
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "form": form
    }
    return render_template("addItem.html", **content)
###########-------------ADD BORROW-------------#####################


###########-------------EDIT ITEM-------------#####################
@app.route("/edytujPrzedmiot/<int:num>", methods=["GET", "POST"])
@login_required
def editItem(num):
    item = db.get_or_404(Item, num)
    x = item.category_id
    if item.status == "borrow":
        for borrow in item.borrow:
            borrow = borrow
        form = itemFormForBorrow(title=item.title, author=item.author, borrower=borrow.borrower, category=item.category.name, store=item.store.name, finish_date=datetime.strptime(borrow.to_date, "%Y-%m-%d").date())
        form.category.choices = [(category.name, category.name) for category in db.session.execute(db.select(Category)).scalars().all()]
        form.store.choices = [(store.name, store.name) for store in db.session.execute(db.select(Store)).scalars().all()]
    else:
        form = itemForm(title=item.title, author=item.author, category=item.category.name, store=item.store.name)
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
        return redirect(url_for("getCategory", num=x))
    content = {
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "form": form
    }
    return render_template("addItem.html", **content)
###########-------------EDIT ITEM-------------#####################



###########-------------DELETE BORROW-------------#####################

@app.route("/oddaj/<int:num>", methods=["POST", "GET"])
@login_required
@confirmPassword
def deleteBorrow(num):
    alerts = []
    item = db.get_or_404(Item, num)
    for borrow in item.borrow:
        borrow = borrow
    db.session.delete(borrow)
    item.status = "noBorrow"
    db.session.commit()
    return redirect(url_for("getCategory", num=item.category_id))
###########-------------DELETE BORROW-------------#####################


###########-------------DELETE ITEM-------------#####################
@app.route("/usunPrzedmiot/<int:num>", methods=["POST", "GET"])
@login_required
@confirmPassword
def deleteItem(num):
    item = db.get_or_404(Item, num)
    if item.borrow:
        return abort(404)
    item.status = "deleted"
    db.session.commit()
    return redirect(url_for("getCategory", num=item.category_id))
###########-------------DELETE ITEM-------------#####################



###########-------------DELETE CATEGORY-------------#####################
@login_required
@app.route("/usunKategorie", methods=["GET", "POST"])
def deleteCategory():
    form = selectCategoryForm()
    form.categories.choices = [(category.name, category.name) for category in db.session.execute(db.select(Category)).scalars().all()]
    if form.validate_on_submit():
        category_name = form.categories.data
        category = db.session.execute(db.select(Category).where(Category.name == category_name)).scalar()
        db.session.delete(category)
        db.session.commit()
        return redirect(request.referrer)
    content = {
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "form": form
    }
    return render_template("addItem.html", **content)
###########-------------DELETE CATEGORY-------------#####################

###########-------------DELETE STORE-------------#####################
@login_required
@app.route("/usunMagazyn", methods=["GET", "POST"])
def deleteStore():
    form = selectStoreForm()
    form.stores.choices = [(store.name, store.name) for store in db.session.execute(db.select(Store)).scalars().all()]
    if form.validate_on_submit():
        store_name = form.stores.data
        store = db.session.execute(db.select(Store).where(Store.name == store_name)).scalar()
        db.session.delete(store)
        db.session.commit()
        return redirect(request.referrer)
    content = {
        "logged_in": current_user.is_authenticated,
        "categories": db.session.execute(db.select(Category)).scalars().all(),
        "stores": db.session.execute(db.select(Store)).scalars().all(),
        "form": form
    }
    return render_template("addItem.html", **content)
###########-------------DELETE STORE-------------#####################


@app.route("/przywróćPrzedmiot/<int:num>")
@login_required
def restoreItem(num):
    item = db.get_or_404(Item, num)
    item.status = "noBorrow"
    db.session.commit()
    return redirect(url_for("deletedItem"))


if __name__  == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(3000))
