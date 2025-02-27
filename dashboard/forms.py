# dashboard/forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, IntegerField, BooleanField
from wtforms.validators import DataRequired, IPAddress, Optional, NumberRange, URL

class IPForm(FlaskForm):
    ip_address = StringField('IP Address', validators=[DataRequired(), IPAddress()])
    description = StringField('Description')
    check_now = BooleanField('Check Now') #Изменил на BooleanField
    submit = SubmitField('Add IP')

class WebsiteForm(FlaskForm):
    url = StringField('URL', validators=[DataRequired(), URL()])
    check_now = BooleanField('Check Now')
    submit = SubmitField('Add Website')

class CertificateForm(FlaskForm):
    domain = StringField('Domain', validators=[DataRequired()])
    port = IntegerField('Port', validators=[Optional(), NumberRange(min=1, max=65535)], default=443)
    check_now = BooleanField('Check Now')
    submit = SubmitField('Add Certificate')

class DNSForm(FlaskForm):
    domain = StringField('Domain', validators=[DataRequired()])
    check_now = BooleanField('Check Now')
    submit = SubmitField('Add DNS Record')

class PortScanForm(FlaskForm):
    ip_address = StringField('IP Address', validators=[DataRequired(), IPAddress()])
    ports = StringField('Ports (comma-separated)', validators=[DataRequired()])
    check_now = BooleanField('Check Now')
    submit = SubmitField('Add Port Scan')

class SecurityHeadersForm(FlaskForm):
     url = StringField('URL', validators=[DataRequired(), URL()])
     check_now = BooleanField('Check Now')
     submit = SubmitField('Add')

class TaskForm(FlaskForm):
    task_name = StringField('Task Name', validators=[DataRequired()])
    function = StringField('Function', validators=[DataRequired()])
    interval = IntegerField('Interval', validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField('Add Task')