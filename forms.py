from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField, DateField, PasswordField, BooleanField
from wtforms.validators import DataRequired, ValidationError
from datetime import datetime

class categoriesForm(FlaskForm):
    name = StringField("Nazwa kategorii", validators=[DataRequired(message="Wpisz dane")])
    submit = SubmitField("zatwierdź")

class storesForm(FlaskForm):
    name = StringField("Nazwa magazynu", validators=[DataRequired(message="Wpisz dane")])
    submit = SubmitField("zatwierdź")

class therapyForm(FlaskForm):
    name = StringField("Nazwa terapii", validators=[DataRequired(message="Wpisz dane")])
    submit = SubmitField("zatwierdź")

class teacherForm(FlaskForm):
    name = StringField("Nazwa terapeuty", validators=[DataRequired(message="Wpisz dane")])
    submit = SubmitField("zatwierdź")

class dateForm(FlaskForm):
    name = StringField("Nazwa", validators=[DataRequired(message="Wpisz dane")])
    date = DateField("Data ważności", validators=[DataRequired(message="Wpisz dane")])
    submit = SubmitField("zatwierdź")

class borrowForm(FlaskForm):
    borrower = StringField("Pożyczający", validators=[DataRequired(message="Wpisz dane")])
    finish_date = DateField("Data oddania", validators=[DataRequired(message="Wpisz dane")])
    submit = SubmitField("zatwierdź")

    def validate_finish_date(self, field):
        if field.data and field.data < datetime.now().date():
            raise ValidationError('Data musi być równa lub późniejsza od dnia dzisiejszego!')



class itemForm(FlaskForm):
    title = StringField("Tytuł", validators=[DataRequired(message="Wpisz dane")])
    author = StringField("Autor/wydawnictwo", validators=[DataRequired(message="Wpisz dane")])
    category = SelectField("Kategoria", choices=[], validators=[DataRequired(message="Wpisz dane")])
    store = SelectField("Magazyn", choices=[], validators=[DataRequired(message="Wpisz dane")])
    submit = SubmitField("zatwierdź")

class itemFormForBorrow(FlaskForm):
    title = StringField("Tytuł", validators=[DataRequired(message="Wpisz dane")])
    author = StringField("Autor/wydawnictwo", validators=[DataRequired(message="Wpisz dane")])
    borrower = StringField("Pożyczający", validators=[DataRequired(message="Wpisz dane")])
    category = SelectField("Kategoria", choices=[], validators=[DataRequired(message="Wpisz dane")])
    store = SelectField("Magazyn", choices=[], validators=[DataRequired(message="Wpisz dane")])
    finish_date = DateField("Data oddania", validators=[DataRequired(message="Wpisz dane")])
    submit = SubmitField("zatwierdź")

    def validate_finish_date(self, field):
        if field.data and field.data < datetime.now().date():
            raise ValidationError('Data musi być równa lub późniejsza od dnia dzisiejszego!')

class selectCategoryForm(FlaskForm):
    categories = SelectField("Kategoria", choices=[], validators=[DataRequired(message="Wpisz dane")])
    submit = SubmitField("zatwierdź")

class selectForm(FlaskForm):
    name = SelectField("Nazwa", choices=[], validators=[DataRequired(message="Wpisz dane")])
    submit = SubmitField("zatwierdź")

class addAcitivityForm(FlaskForm):
    name = StringField("Nazwa opieki", validators=[DataRequired(message="Wpisz dane")])
    start_date = DateField("Data rozpoczęcie opieki", validators=[DataRequired(message="Wpisz dane")])
    submit = SubmitField("zatwierdź")

class endAcitivityForm(FlaskForm):
    end_date = DateField("Data zakończenia opieki", validators=[DataRequired(message="Wpisz dane")])
    submit = SubmitField("zatwierdź")

class dateSegregatorForm(FlaskForm):
    start_date = DateField("Od", validators=[DataRequired(message="Wpisz dane")])
    end_date = DateField("Do", validators=[DataRequired(message="Wpisz dane")])
    submit = SubmitField("zatwierdź")


class ipetForm(FlaskForm):
    date = DateField("Data ważności", validators=[DataRequired(message="Wpisz dane")])
    submit = SubmitField("zatwierdź")

class lateSegregatorForm(FlaskForm):
    late = SelectField("Przedawnione", choices=[("wszystko", "Wszystkie"), ("umowa", "Umowa"), ("ipet", "IPET"), ("wofu", "WOFU"), ("orzeczenie", "Orzeczenie")], validators=[DataRequired(message="Wpisz dane")])
    submit = SubmitField("zatwierdź")

class missSegregatorForm(FlaskForm):
    miss = SelectField("Braki", choices=[("wszystko", "Wszystkie"), ("umowa", "Umowa"), ("ipet", "IPET"), ("wofu", "WOFU"), ("orzeczenie", "Orzeczenie"), ("kartazgłoszeń", "Karta zgłoszeń"), ("terapia", "Terapia"), ("terapeuta", "Terapeuta")], validators=[DataRequired(message="Wpisz dane")])
    submit = SubmitField("zatwierdź")



class addPermissionToUserForm(FlaskForm):
    reading_item = BooleanField("Czytanie przedmiotów")
    editing_item = BooleanField("Edycja przedmiotów")
    deleting_item = BooleanField("Usuwanie przedmiotów")
    adding_item = BooleanField("Dodawanie przedmiotów")
    reading_child = BooleanField("Czytanie dzieci")
    editing_child = BooleanField("Edycja dzieci")
    deleting_child = BooleanField("Usuwanie dzieci")
    adding_child = BooleanField("Dodawanie dzieci")
    submit = SubmitField("zatwierdź")

class inputChildrenForm(FlaskForm):
    name = StringField("Imię i nazwisko", validators=[DataRequired(message="Wpisz dane")])
    birth = DateField("Data urodzenia", validators=[DataRequired(message="Wpisz dane")])
    submit = SubmitField("dodaj")
    def validate_finish_date(self, field):
        if field.data and field.data > datetime.now().date():
            raise ValidationError('Data musi być mniejsza od dnia dzisiejszego!')

class selectStoreForm(FlaskForm):
    stores = SelectField("Magazyn", choices=[], validators=[DataRequired(message="Wpisz dane")])
    submit = SubmitField("zatwierdź")


class confirmReturnForm(FlaskForm):
    password = PasswordField("Wprowadź hasło", validators=[DataRequired(message="Wpisz dane")])
    submit = SubmitField("zatwierdź")

class managementForm(FlaskForm):
    name = StringField("Wprowadź zarządzenie", validators=[DataRequired(message="Wpisz dane")])
    submit = SubmitField("zatwierdź")