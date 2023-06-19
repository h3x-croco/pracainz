from flask import Flask, render_template, flash, redirect, request, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json
import psycopg2
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user, login_manager
from webforms import FalsePositiveForm, ReportVulnForm, LoginForm, RegisterFrom, FalsePositiveForm, FalsePositiveAcceptForm, FalsePositiveRejectForm, UserAcceptForm, UserRejectForm, ConsultingForm
from functools import wraps
from flask import abort


app = Flask(__name__)

if __name__ == '__main__':
    app.run(debug=True)


app.config['SECRET_KEY'] = "supersecretkeyxx"


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
@login_manager.user_loader


def load_user(user_id):
    return User.get(user_id)



@app.cli.command()


# Tylko dla adminów













@app.route('/test', methods=['GET', 'POST'])
@login_required
def test():
    user = current_user.user_name
    conn = psycopg2.connect(host='localhost', port='5432', database='cmdb', user='postgres', password='ZKApUMahTLoHyqkMvJovBpyvw2KWQe')
    cur = conn.cursor()
    select_asset_for_user = """SELECT asset_owner.email, asset.hostname 
FROM asset
INNER JOIN asset_owner on asset.asset_owner_id=asset_owner.asset_owner_id
WHERE asset_owner.email =%s;"""
    cur.execute(select_asset_for_user, [user])
    assets_data = cur.fetchall()
    conn.commit()
    cur.close()
    conn.close()
    values = [item[1] for item in assets_data]
    print(values)
    connection = psycopg2.connect(user='postgres',
                                            password='ZKApUMahTLoHyqkMvJovBpyvw2KWQe',
                                            host='localhost',
                                            port='5432',
                                            database='nexpose')
    cursor = connection.cursor()
    print("Polaczenie do bazy danych ")
    param_placeholders = ','.join(['%s'] * len(values))
    postgres_insert_query = """SELECT VULNS_FOUND.asset_id, ASSET.host_name, SOLUTION.summary, VULN.title, VULN.severity, VULN.cvss_score
FROM fact_asset_vulnerability_instance AS VULNS_FOUND
INNER JOIN dim_asset AS ASSET ON ASSET.asset_id=VULNS_FOUND.asset_id
INNER JOIN dim_vulnerability AS VULN ON VULNS_FOUND.vulnerability_id=VULN.vulnerability_id
INNER JOIN dim_vulnerability_solution ON dim_vulnerability_solution.vulnerability_id=VULN.vulnerability_id
INNER JOIN dim_solution AS SOLUTION ON SOLUTION.solution_id=dim_vulnerability_solution.solution_id WHERE ASSET.host_name IN ({})""".format(param_placeholders)

    cursor.execute(postgres_insert_query, values)
    results = cursor.fetchall()
	#print(results)
    grouped_data = {}
    for row in results:
        asset_id, host_name, summary, title, severity, cvss_score = row
        if host_name not in grouped_data:
            grouped_data[host_name] = []
        grouped_data[host_name].append({
        "asset_id": asset_id,
		"summary": summary,
		"title": title,
		"severity": severity,
		"cvss_score": cvss_score
		})
    json_data = json.dumps(grouped_data)
    data = json.loads(json_data)
    print(json_data)
    for key, value in data.items():
        print("key:", key)
        for item in value:
            print("Title:", item["title"])

    connection.commit()
    cursor.close()
    connection.close()
    return render_template('test.html', user=user, data=data)



@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/')
def index():
    return render_template("index.html")


# Web page error handlers - Error 404
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Web page error handlers - Error 500
@app.errorhandler(500)
def page_not_found(e):
    return render_template('500.html'), 500



@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash("You have been logged out!")
    return redirect(url_for('login'))



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if True:
        user_name = form.user_name.data
        password = form.password.data

        conn = psycopg2.connect(
            host='localhost',
            port='5432',
            database='vulnmapp',
            user='postgres',
            password='ZKApUMahTLoHyqkMvJovBpyvw2KWQe'
        )
        cursor = conn.cursor()
        select_user = """SELECT * FROM users WHERE user_name=%s;"""
        cursor.execute(select_user, [user_name])
        user = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()

        if user is not None:
            user_id = user[0]
            user_password = user[2]
            user_role = user[3]
            if check_password_hash(user_password, password):
                # Tworzenie obiektu użytkownika na podstawie danych z bazy danych
                user_obj = User(user_id, user_name, user_password, user_role)
                login_user(user_obj)
                flash("Login successful")
                return redirect(url_for('dashboard'))
            else:
                flash("Wrong password - try again")
    
    return render_template("login.html", form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
        form = RegisterFrom()
        if request.method == 'POST':
            if form.validate_on_submit():
                user_name = form.user_name.data
                password = form.password.data
                return render_template("register.html", form=form, user_name=user_name, password=password)
            return render_template("register.html", form=form)
        return render_template("register.html", form=form)


@app.route('/register/summary', methods=['GET', 'POST'])
def registerSummary():
    if request.method == 'POST':
        user_name = request.form.get('user_name')
        password = request.form.get('password')
        password_hash = generate_password_hash(password)
        # Baza danych
        conn2 = psycopg2.connect(host='localhost',
                                        port='5432',
                                        database='vulnmapp',
                                        user='postgres',
                                        password='ZKApUMahTLoHyqkMvJovBpyvw2KWQe')
        cursor2 = conn2.cursor()
        search_user = """SELECT user_name FROM public.users WHERE user_name=%s;"""
        cursor2.execute(search_user, [user_name])
        found_user = cursor2.fetchone()
        conn2.commit()
        cursor2.close()
        conn2.close()
        if found_user == None:
            conn = psycopg2.connect(host='localhost',
                                        port='5432',
                                        database='vulnmapp',
                                        user='postgres',
                                        password='ZKApUMahTLoHyqkMvJovBpyvw2KWQe')
            cursor = conn.cursor()
            insert_user = """INSERT INTO public.users(user_name, password) VALUES (%s, %s);"""
            insert_data = (user_name, password_hash)
            cursor.execute(insert_user, insert_data)     
            conn.commit()
            cursor.close()
            conn.close()
            flash('Uzytkownik dodany')
            return render_template('registerSummary.html', user_name=user_name)
        flash('Uzytkownik nie zostal dodany')
        return render_template('registerSummary.html')
    return render_template('registerSummary.html')



# Route to page with consulting request with passing information about vulnerability title and host

@app.route('/requestConsulting', methods=['GET', 'POST'])
@login_required
def requestConsulting():
    if request.method == 'POST':
        title = request.form.get('title')
        host = request.form.get('host')
        comment = request.form.get('comment')
        owner = request.form.get('owner')
        form = ConsultingForm()
        if form.validate_on_submit():
            title = form.title.data
            host = form.host.data
            comment = form.comment.data
            owner = form.owner.data
            return render_template("requestConsulting.html", 
                               form=form, title=title, host=host,
                                owner=owner, comment=comment)
        return render_template("requestConsulting.html", form=form,
                               title=title, host=host)
    return render_template("requestConsulting.html", form=form, title=title,
                            host=host, comment=comment)


@app.route('/requestConsulting/summary', methods=['GET', 'POST'])
@login_required
def requestConsultingSummary():
    if request.method == 'POST':
        title = request.form.get('title')
        host = request.form.get('host')
        comment = request.form.get('comment')
        owner = request.form.get('owner')
        status = 0
        time = datetime.now()
        create_time = time.strftime("%Y-%m-%d %H:%M:%S")
        # Baza danych
        conn = psycopg2.connect(host='localhost',
                                port='5432',
                                database='vulnmapp',
                                user='postgres',
                                password='ZKApUMahTLoHyqkMvJovBpyvw2KWQe')
        cursor = conn.cursor()
        insert_query_falsepositive = """ INSERT INTO consultings(
	host, title, comment, create_date, status, owner)
	VALUES (%s, %s, %s, %s, %s, %s); """
        data_to_insert = (host, title, comment, create_time, status, owner )
        cursor.execute(insert_query_falsepositive, data_to_insert)
        conn.commit()
        cursor.close()
        conn.close()
        return render_template("requestConsultingSummary.html", title=title, host=host,
                                comment=comment, status=status, create_time=create_time, owner=owner)
    return render_template("requestConsultingSummary.html")















@app.route('/getConsultings/open', methods=['GET', 'POST'])
@login_required
def getConsultingsOpen():
    conn = psycopg2.connect(host='localhost',
                                port='5432',
                                database='vulnmapp',
                                user='postgres',
                                password='ZKApUMahTLoHyqkMvJovBpyvw2KWQe')
    cursor = conn.cursor()
    # Statusy: 0 - Open (some action to do), 1- Accepted, 2 - Rejected
    select_consultings = """SELECT * FROM consultings WHERE status='Otwarte'"""
    cursor.execute(select_consultings)
    all_consultings = cursor.fetchall()
    conn.commit()
    cursor.close()
    conn.close()
    return render_template('getConsultingsOpen.html', all_consultings=all_consultings)













# Strona z miejscem do wprowadzenia komentarza
# dlaczego jest to false positive
# host i title są pobierane z poprzedniej strony
# pola host i title są już niezmienialne dla usera
@app.route('/reportFalsePositive', methods=['GET', 'POST'])
@login_required
def reportFalsePositive():
    if request.method == 'POST':
        title = request.form.get('title')
        host = request.form.get('host')
        form = FalsePositiveForm()
        if form.validate_on_submit():
            title = form.title.data
            host = form.host.data
            comment = form.comment.data
            return render_template("reportFalsePositive.html", 
                               form=form, title=title, host=host, comment=comment)
        return render_template("reportFalsePositive.html", form=form,
                               title=title, host=host)
    return render_template("reportFalsePositive.html", form=form, title=title,
                            host=host, comment=comment)




@app.route('/reportFalsePositive/summary', methods=['GET', 'POST'])
@login_required
def reportFalsePositiveSummary():
    if request.method == 'POST':
        title = request.form.get('title')
        host = request.form.get('host')
        comment = request.form.get('comment')
        status = 0
        time = datetime.now()
        create_time = time.strftime("%Y-%m-%d %H:%M:%S")
        # Baza danych
        conn = psycopg2.connect(host='localhost',
                                port='5432',
                                database='vulnmapp',
                                user='postgres',
                                password='ZKApUMahTLoHyqkMvJovBpyvw2KWQe')
        cursor = conn.cursor()
        insert_query_falsepositive = """ INSERT INTO falsepositive(
	hostname, title, status, comment, create_time)
	VALUES (%s, %s, %s, %s, %s); """
        data_to_insert = (host, title, status, comment, create_time)
        cursor.execute(insert_query_falsepositive, data_to_insert)
        conn.commit()
        cursor.close()
        conn.close()
        return render_template("reportFalsePositiveSummary.html", title=title, host=host,
                                comment=comment, status=status, create_time=create_time)
    return render_template("reportFalsePositiveSummary.html")


# Wyświetlenie listy wszystkich false positive - wszystkie statusy
@app.route('/getFalsePositive', methods=['GET', 'POST'])
@login_required
def getFalsePositive():
    conn = psycopg2.connect(host='localhost',
                                port='5432',
                                database='vulnmapp',
                                user='postgres',
                                password='ZKApUMahTLoHyqkMvJovBpyvw2KWQe')
    cursor = conn.cursor()
    # Statusy: 0 - Open (some action to do), 1- Accepted, 2 - Rejected
    select_falsePositive = """SELECT * FROM falsepositive;"""
    cursor.execute(select_falsePositive)
    all_false_positive = cursor.fetchall()
    conn.commit()
    cursor.close()
    conn.close()
    return render_template('getFalsePositive.html', all_false_positive=all_false_positive)



# Wyświetlenie listy wszystkich false positive - tylko open
@app.route("/getFalsePositive/open")
@login_required 
def getFalsePositiveOpen():
    conn = psycopg2.connect(host='localhost',
                                port='5432',
                                database='vulnmapp',
                                user='postgres',
                                password='ZKApUMahTLoHyqkMvJovBpyvw2KWQe')
    cursor = conn.cursor()
    # Statusy: 0 - Open (some action to do), 1- Accepted, 2 - Rejected
    select_falsePositive = """SELECT * FROM falsepositive WHERE status = 0;"""
    cursor.execute(select_falsePositive)
    all_false_positive_open = cursor.fetchall()
    conn.commit()
    cursor.close()
    conn.close()
    return render_template("getFalsePositiveOpen.html", all_false_positive_open=all_false_positive_open)


@app.route("/getFalsePositive/accepted")
@login_required
def getFalsePositiveAccepted():
    conn = psycopg2.connect(host='localhost',
                                port='5432',
                                database='vulnmapp',
                                user='postgres',
                                password='ZKApUMahTLoHyqkMvJovBpyvw2KWQe')
    cursor = conn.cursor()
    # Statusy: 0 - Open (some action to do), 1- Accepted, 2 - Rejected
    select_falsePositive = """SELECT * FROM falsepositive WHERE status = 1;"""
    cursor.execute(select_falsePositive)
    all_accepted_false_positives = cursor.fetchall()
    conn.commit()
    cursor.close()
    conn.close()
    return render_template("getFalsePositiveAccepted.html", 
                           all_accepted_false_positives=all_accepted_false_positives)


@app.route("/getFalsePositive/rejected")
@login_required
def getFalsePositiveRejected():
    conn = psycopg2.connect(host='localhost',
                                port='5432',
                                database='vulnmapp',
                                user='postgres',
                                password='ZKApUMahTLoHyqkMvJovBpyvw2KWQe')
    cursor = conn.cursor()
    # Statusy: 0 - Open (some action to do), 1- Accepted, 2 - Rejected
    select_falsePositive = """SELECT * FROM falsepositive WHERE status = 2;"""
    cursor.execute(select_falsePositive)
    all_rejected_false_positives = cursor.fetchall()
    conn.commit()
    cursor.close()
    conn.close()
    return render_template("getFalsePositiveRejected.html", 
                           all_rejected_false_positives=all_rejected_false_positives)


@app.route("/getFalsePositive/<id>")
@login_required
def getFalsePositiveDetails(id):
    conn = psycopg2.connect(host='localhost',
                                port='5432',
                                database='vulnmapp',
                                user='postgres',
                                password='ZKApUMahTLoHyqkMvJovBpyvw2KWQe')
    cursor = conn.cursor()
    # Statusy: 0 - Open (some action to do), 1- Accepted, 2 - Rejected
    select_falsePositive = """SELECT * FROM falsepositive WHERE id = %s;;"""
    cursor.execute(select_falsePositive, [id])
    false_positive_details = cursor.fetchall()
    conn.commit()
    cursor.close()
    conn.close()
    return render_template("getFalsePositiveDetails.html",
                           false_positive_details=false_positive_details)



# Formularz do odrzucnia false positive
@app.route("/getFalsePositive/reject", methods=['GET', 'POST'])
@login_required
def getFalsePositiveRejectForm():
    if request.method == 'POST':
        title = request.form.get('title')
        host = request.form.get('host')
        form = FalsePositiveRejectForm()
        if form.validate_on_submit():
            title = form.title.data
            host = form.host.data
            comment = form.comment.data
            return render_template("getFalsePositiveRejectForm.html", 
                               form=form, title=title, host=host, comment=comment)
        return render_template("getFalsePositiveRejectForm.html", 
                                   form=form, title=title, host=host)
    return render_template("getFalsePositiveRejectForm.html", 
                               form=form, title=title, host=host, comment=comment)

# Formularz do odrzucenia false positive
@app.route("/getFalsePositive/accept", methods=['GET', 'POST'])
@login_required
def getFalsePositiveAcceptForm():
        if request.method == 'POST':
            id = request.form.get('id')
            title = request.form.get('title')
            host = request.form.get('host')
            form = FalsePositiveAcceptForm()
            if form.validate_on_submit():
                title = form.title.data
                host = form.host.data
                comment = form.comment.data
                id = form.id.data
                return render_template("getFalsePositiveAcceptForm.html", 
                               form=form, id=id, title=title, host=host, comment=comment)
            return render_template("getFalsePositiveAcceptForm.html", 
                                   form=form, id=id, title=title, host=host)
        return render_template("getFalsePositiveAcceptForm.html", 
                               form=form, id=id, title=title, host=host, comment=comment)

@app.route("/getFalsePositive/accept/summary", methods=['GET', 'POST'])
@login_required
def getFalsePositiveAcceptFormSummary():
    if request.method == 'POST':
        title = request.form.get('title')
        host = request.form.get('host')
        comment = request.form.get('comment')
        id = request.form.get('id')
        status = 1
        time = datetime.now()
        last_update = time.strftime("%Y-%m-%d %H:%M:%S")
        # Baza danych
        conn = psycopg2.connect(host='localhost',
                                port='5432',
                                database='vulnmapp',
                                user='postgres',
                                password='ZKApUMahTLoHyqkMvJovBpyvw2KWQe')
        cursor = conn.cursor()
        update_query_falsepositive = """UPDATE public.falsepositive SET status=1, comment_consultant=%s, last_update=%s WHERE id = %s;"""
        data_to_insert = (comment, last_update, id)
        cursor.execute(update_query_falsepositive, data_to_insert)
        conn.commit()
        cursor.close()
        conn.close()
    return render_template('getFalsePositiveAcceptFormSummary.html', 
                           title=title, host=host,comment=comment,
                             id=id, status=status, create_time=last_update)



@app.route("/getFalsePositive/reject/summary", methods=['GET', 'POST'])
@login_required
def getFalsePositiveRejectFormSummary():
    return render_template('xxx.html')


# Route to page with details about specific vulnerability
@app.route('/vulnerabilities/<id>')
@login_required
def get_internal_vulnerability(id):
    conn = psycopg2.connect(host='localhost',
                                port='5432',
                                database='internal',
                                user='postgres',
                                password='ZKApUMahTLoHyqkMvJovBpyvw2KWQe')
    cursor = conn.cursor()
    select_vulnerability = """SELECT * FROM vulnerability WHERE id = %s;"""
    cursor.execute(select_vulnerability, [id])
    vulnerability = cursor.fetchall()
    conn.commit()
    cursor.close()
    conn.close()
    return render_template("vulnerability.html", vulnerability=vulnerability)



@app.route('/vulnerabilities/', methods=['GET', 'POST'])
@login_required
def get_internal_vulnerabilities():
    # zasymulowane dane z nazwami hostów - będą one wyciągane z bazy danych
    hosts = ('HVMWAW65411', 'HVMWAW65435', 'HVMWAW65993')
    conn = psycopg2.connect(host='localhost',
                                port='5432',
                                database='vulnmapp',
                                user='postgres',
                                password='ZKApUMahTLoHyqkMvJovBpyvw2KWQe')
    cursor = conn.cursor()
    select_vulnerabilities = """SELECT * FROM consultings;"""
    cursor.execute(select_vulnerabilities)
    vulnerabilities = cursor.fetchall()
    conn.commit()
    cursor.close()
    conn.close()
    return render_template("vulnerabilities.html", vulnerabilities=vulnerabilities, hosts=hosts)



@app.route('/vulnerabilities/vulnerability/add/summary', methods=['GET', 'POST'])
@login_required
def vuln_add_summary():
    return render_template('vuln_add_summary.html')



@app.route('/vulnerabilities/vulnerability/add', methods=['GET', 'POST'])
@login_required
def vuln_report():
    form = ReportVulnForm()
    if form.validate_on_submit():
        title = form.title.data
        proof = form.proof.data
        solution = form.solution.data
        discovery_time = datetime.now()
        host = form.host.data
        status_id = 1
        # Wyczyść formularz
        form.title.data = ''
        form.proof.data = ''
        form.solution.data = ''
        form.host.data = ''
        form.status_id.data = ''
        form.discovery_time.data = ''
        # flash("Form submitted successfully")
        return redirect(url_for('vuln_report'))
    # Przypisz wartości do formularza, jeśli przesłano dane
    title = request.args.get('title', '')
    host = request.args.get('host', '')
    proof = request.args.get('proof', '')
    solution = request.args.get('solution', '')
    return render_template('form_vulnerability.html', form=form, title=title, host=host, proof=proof, solution=solution)


# Wyświetlenie wszystkich użytkowników
@app.route('/getUsers', methods=['GET', 'POST'])
@login_required
def getUsers():
    conn = psycopg2.connect(host='localhost',
                                port='5432',
                                database='vulnmapp',
                                user='postgres',
                                password='ZKApUMahTLoHyqkMvJovBpyvw2KWQe')
    cursor = conn.cursor()
    # Statusy: 0 - Open (some action to do), 1- Accepted, 2 - Rejected
    select_users = """SELECT * FROM users;"""
    cursor.execute(select_users)
    all_get_users = cursor.fetchall()
    conn.commit()
    cursor.close()
    conn.close()
    return render_template('getUsers.html', all_get_users=all_get_users)

@app.route('/getUsers/toverify', methods=['GET', 'POST'])
@login_required
def getUsersToVerify():
    conn = psycopg2.connect(host='localhost',
                                port='5432',
                                database='vulnmapp',
                                user='postgres',
                                password='ZKApUMahTLoHyqkMvJovBpyvw2KWQe')
    cursor = conn.cursor()
    # Statusy: 0 - Open (some action to do), 1- Accepted, 2 - Rejected
    select_users = """SELECT * FROM users WHERE role is NULL;"""
    cursor.execute(select_users)
    all_get_users = cursor.fetchall()
    conn.commit()
    cursor.close()
    conn.close()
    return render_template('getUsersToVerify.html', all_get_users=all_get_users)

@app.route('/getUsers/accept', methods=['GET', 'POST'])
@login_required
def getUsersAcceptForm():
        if request.method == 'POST':
            id = request.form.get('id')
            email = request.form.get('email')
            role = request.form.get('role')
            form = UserAcceptForm()
            if form.validate_on_submit():
                id = form.id.data
                email = form.email.data
                role = form.role.data
                return render_template("getUsersAcceptForm.html", 
                               form=form, id=id, email=email, role=role)
            return render_template("getUsersAcceptForm.html", 
                                   form=form, id=id, email=email, role=role)
        return render_template("getUsersAcceptForm.html", 
                               form=form, id=id, email=email, role=role)


@app.route('/getUsers/reject', methods=['GET', 'POST'])
@login_required
def getUsersRejectForm():
        if request.method == 'POST':
            id = request.form.get('id')
            email = request.form.get('email')
            form = UserRejectForm()
            if form.validate_on_submit():
                id = form.id.data
                email = form.email.data
                return render_template("getUsersRejectForm.html", 
                               form=form, id=id, email=email)
            return render_template("getUsersRejectForm.html", 
                                   form=form, id=id, email=email)
        return render_template("getUsersRejectForm.html", 
                               form=form, id=id, email=email)


@app.route('/getUsers/accept/summary', methods=['GET', 'POST'])
@login_required
def getUsersAcceptFormSummary():
    if request.method == 'POST':
        id = request.form.get('id')
        role = request.form.get('role')
        email = request.form.get('email')
        # Baza danych
        conn = psycopg2.connect(host='localhost',
                                port='5432',
                                database='vulnmapp',
                                user='postgres',
                                password='ZKApUMahTLoHyqkMvJovBpyvw2KWQe')
        cursor = conn.cursor()
        update_query_user = """UPDATE public.users SET role=%s WHERE id = %s;"""
        data_to_insert = (role, id)
        cursor.execute(update_query_user, data_to_insert)
        conn.commit()
        cursor.close()
        conn.close()
    return render_template('getUsersAcceptFormSummary.html', 
                           id=id, role=role, email=email)

@app.route('/getUsers/reject/summary', methods=['GET', 'POST'])
@login_required
def getUsersRejectFormSummary():
    if request.method == 'POST':
        id = request.form.get('id')
        email = request.form.get('email')
        # Baza danych
        conn = psycopg2.connect(host='localhost',
                                port='5432',
                                database='vulnmapp',
                                user='postgres',
                                password='ZKApUMahTLoHyqkMvJovBpyvw2KWQe')
        cursor = conn.cursor()
        update_query_user = """DELETE FROM public.users WHERE id = %s;"""
        cursor.execute(update_query_user, [id])
        conn.commit()
        cursor.close()
        conn.close()
    return render_template('getUsersRejectFormSummary.html', 
                           id=id, email=email)


@app.route('/getUsers/<id>', methods=['GET', 'POST'])
@login_required
def getUsersDetails(id):
        conn = psycopg2.connect(host='localhost',
                                port='5432',
                                database='vulnmapp',
                                user='postgres',
                                password='ZKApUMahTLoHyqkMvJovBpyvw2KWQe')
        cursor = conn.cursor()
        select_user = """SELECT * FROM users WHERE id = %s;"""
        cursor.execute(select_user, [id])
        user = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()
        return render_template("getUsersDetails.html", user=user)
















### ======================================= ###
###                 CLASES                  ###
### ======================================= ###

class User(UserMixin):
    def __init__(self, id, user_name, password, role):
        self.id = id
        self.user_name = user_name
        self.password = password
        self.role = role

    def is_active(self):
        return True  # Możesz dostosować implementację w zależności od logiki aktywacji konta

    @staticmethod
    def get(user_id):
        conn = psycopg2.connect(host='localhost', port='5432', database='vulnmapp', user='postgres', password='ZKApUMahTLoHyqkMvJovBpyvw2KWQe')
        cursor = conn.cursor()
        select_user = """SELECT * FROM users WHERE id = %s;"""
        cursor.execute(select_user, [user_id])
        result = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()

        if result:
            return User(result[0], result[1], result[2], result[3])
        else:
            return None

    # Pozostałe metody interfejsu UserMixin, takie jak is_authenticated(), is_anonymous(), get_id(), itd.


