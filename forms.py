from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField, DateField
from wtforms.validators import DataRequired, ValidationError
from datetime import datetime

class categoriesForm(FlaskForm):
    name = StringField("name", validators=[DataRequired()])
    submit = SubmitField("submit")

class storesForm(FlaskForm):
    name = StringField("name", validators=[DataRequired()])
    submit = SubmitField("submit")

class borrowForm(FlaskForm):
    borrower = StringField("Pożyczający", validators=[DataRequired()])
    finish_date = DateField("Data oddania", validators=[DataRequired()])
    submit = SubmitField("Zatwierdź")

    def validate_finish_date(self, field):
        if field.data and field.data < datetime.now().date():
            raise ValidationError('Finish date must be equal to or later than start date.')

class itemForm(FlaskForm):
    title = StringField("title", validators=[DataRequired()])
    author = StringField("author/wydawnictwo", validators=[DataRequired()])
    category = SelectField("categories", choices=[], validators=[DataRequired()])
    store = SelectField("stores", choices=[], validators=[DataRequired()])
    submit = SubmitField("submit")

class itemFormForBorrow(FlaskForm):
    title = StringField("title", validators=[DataRequired()])
    author = StringField("author/wydawnictwo", validators=[DataRequired()])
    borrower = StringField("Pożyczający", validators=[DataRequired()])
    category = SelectField("categories", choices=[], validators=[DataRequired()])
    store = SelectField("stores", choices=[], validators=[DataRequired()])
    finish_date = DateField("Data oddania", validators=[DataRequired()])
    submit = SubmitField("submit")

    def validate_finish_date(self, field):
        if field.data and field.data < datetime.now().date():
            raise ValidationError('Finish date must be equal to or later than start date.')

class selectCategoryForm(FlaskForm):
    categories = SelectField("Kategorie", choices=[], validators=[DataRequired()])
    submit = SubmitField("submit")


class selectStoreForm(FlaskForm):
    stores = SelectField("Magazyny", choices=[], validators=[DataRequired()])
    submit = SubmitField("submit")