from wtforms import StringField, SubmitField, FileField
from wtforms.validators import DataRequired
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FileField
from wtforms.validators import DataRequired
from flask_wtf import FlaskForm
from wtforms.widgets import TextArea
from wtforms import StringField, SubmitField, EmailField, IntegerField, DateField, PasswordField, BooleanField, ValidationError, SelectField
from wtforms.validators import DataRequired, EqualTo, Length
from flask_wtf import FlaskForm

# Form to add new vulnerability
class FalsePositiveForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    host = StringField('Host', validators=[DataRequired()])
    comment = StringField('Comment', validators=[DataRequired()])
    submit = SubmitField('Submit')

class ConsultingForm(FlaskForm):
    title = StringField('Tytuł', validators=[DataRequired()])
    host = StringField('Nazwa hosta', validators=[DataRequired()])
    comment = StringField('Komentarz', validators=[DataRequired()])
    owner  = StringField('Zgłoś jako', validators=[DataRequired()])
    submit = SubmitField('Submit')

# Form to add new vulnerability
class ReportVulnForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    proof = StringField('Proof', validators=[DataRequired()])
    solution = StringField('Solution', validators=[DataRequired()])
    host = StringField('Host', validators=[DataRequired()])
    status_id = StringField('Status', validators=[DataRequired()])
    discovety_time = StringField('Discvovery time', validators=[DataRequired()])
    submit = SubmitField('Submit')

# Form to login page
class LoginForm(FlaskForm):
    user_name = StringField('Nazwa:', validators=[DataRequired()])
    password = PasswordField('Hasło:', validators=[DataRequired()])
    submit = SubmitField('Zaloguj')


class RegisterFrom(FlaskForm):
    user_name = EmailField('Nazwa użytkownika (e-mail):', validators=[DataRequired()])
    password = PasswordField('Hasło:', validators=[DataRequired()])
    password2 = PasswordField('Powtórz hasło:',
                               validators=[DataRequired(), 
                                EqualTo(password, message='Hasło musi być takie samo!')])
    submit = SubmitField('Zarejestruj się')

# Formularz do zgłaszania False Positive
# status oraz create_time są generowane poza wiedzą użytkownika
class FalsePositiveForm(FlaskForm):
    title = StringField('Tytuł:', validators=[DataRequired()])
    host = StringField('Nazwa hosta:', validators=[DataRequired()])
    status = IntegerField('Status: ', validators=[DataRequired()])
    comment = StringField('Uzasadnienie: ', validators=[DataRequired()])
    create_time = DateField('Data utworzenia: ', validators=[DataRequired()])
    submit = SubmitField('Zgłoś false positive')

# Formularz do zaakceptowania zgłoszonych False Positive
class FalsePositiveAcceptForm(FlaskForm):
    id = IntegerField('ID: ', validators=[DataRequired()])
    title = StringField('Tytuł:', validators=[DataRequired()])
    host = StringField('Nazwa hosta:', validators=[DataRequired()])
    status = IntegerField('Status: ', validators=[DataRequired()])
    comment = StringField('Uzasadnienie: ', validators=[DataRequired()])
    create_time = DateField('Data utworzenia: ', validators=[DataRequired()])
    submit = SubmitField('Zaakceptuj false positive')


# Formularz do odrzucania zgłoszonych False Positive
class FalsePositiveRejectForm(FlaskForm):
    id = IntegerField('ID: ', validators=[DataRequired()])
    title = StringField('Tytuł:', validators=[DataRequired()])
    host = StringField('Nazwa hosta:', validators=[DataRequired()])
    status = IntegerField('Status: ', validators=[DataRequired()])
    comment = StringField('Uzasadnienie: ', validators=[DataRequired()])
    create_time = DateField('Data utworzenia: ', validators=[DataRequired()])
    submit = SubmitField('Odrzuć false positive')




# Formularz do zaakceptowania użytkownika w systemie
class UserAcceptForm(FlaskForm):
    id = IntegerField('ID: ', validators=[DataRequired()])
    email = StringField('E-mail: ', validators=[DataRequired()])
    role = SelectField('Rola: ', choices=[('admin', 'Administrator'), ('consultant', 'Konsultant'), ('assetOwner', 'Asset Owner'), ('pentester', 'Pentester')])
    submit = SubmitField('Zaakceptuj użytkownika')


# Formularz do odrzucania użytkownika w systmie
class UserRejectForm(FlaskForm):
    id = IntegerField('ID: ', validators=[DataRequired()])
    email = StringField('E-mail: ', validators=[DataRequired()])
    submit = SubmitField('Odrzuć użytkownika')