from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_pymongo import PyMongo
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import jwt, datetime

app = Flask(__name__)
app.secret_key = "8e9a274b9a4a977c64a55c3d03342683"

# MongoDB Config
app.config["MONGO_URI"] = "mongodb://localhost:27017/od_system"
mongo = PyMongo(app)

# Mail Config
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='your_email@gmail.com',
    MAIL_PASSWORD='your_app_password'
)
mail = Mail(app)

def generate_token(email, role):
    payload = {
        "email": email,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    }
    return jwt.encode(payload, app.secret_key, algorithm="HS256")

def login_required(role=None):
    def wrapper(fn):
        @wraps(fn)
        def decorated(*args, **kwargs):
            token = session.get("token")
            if not token:
                return redirect(url_for("login"))
            try:
                payload = jwt.decode(token, app.secret_key, algorithms=["HS256"])
                if role and payload.get("role") != role:
                    return redirect(url_for("login"))
            except:
                session.clear()
                return redirect(url_for("login"))
            return fn(*args, **kwargs)
        return decorated
    return wrapper

def send_email(to, subject, body):
    msg = Message(subject, sender=app.config['MAIL_USERNAME'], recipients=[to])
    msg.body = body
    mail.send(msg)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = request.form
        name = data["name"]
        email = data["email"]
        password = generate_password_hash(data["password"])
        role = data["role"]

        if mongo.db.users.find_one({"email": email}):
            return render_template("register.html", error="Email already exists")

        mongo.db.users.insert_one({"name": name, "email": email, "password": password, "role": role})
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = mongo.db.users.find_one({"email": email})

        if user and check_password_hash(user["password"], password):
            token = generate_token(email, user["role"])
            session["token"] = token
            session["role"] = user["role"]
            return redirect(url_for("student_dashboard" if user["role"] == "student" else "teacher_dashboard"))

        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@app.route("/student_dashboard")
@login_required("student")
def student_dashboard():
    return render_template("student_dashboard.html")

@app.route("/my_requests")
@login_required("student")
def my_requests():
    email = jwt.decode(session["token"], app.secret_key, algorithms=["HS256"])["email"]
    requests = list(mongo.db.od_requests.find({"student_email": email}, {"_id": 0}))
    return render_template("my_requests.html", requests=requests)

@app.route("/od_request", methods=["POST"])
@login_required("student")
def od_request():
    email = jwt.decode(session["token"], app.secret_key, algorithms=["HS256"])["email"]
    data = request.form
    mongo.db.od_requests.insert_one({
        "student_email": email,
        "event_name": data["event_name"],
        "event_date": data["event_date"],
        "reason": data["reason"],
        "status": "Pending"
    })
    return redirect(url_for("student_dashboard"))

@app.route("/teacher_dashboard")
@login_required("teacher")
def teacher_dashboard():
    return render_template("teacher_dashboard.html")

@app.route("/view_od_requests")
@login_required("teacher")
def view_od_requests():
    status = request.args.get("status")
    query = {"status": status} if status else {}
    requests = list(mongo.db.od_requests.find(query, {"_id": 0}))
    return jsonify(requests)

@app.route("/update_od_request", methods=["POST"])
@login_required("teacher")
def update_od_request():
    data = request.form
    email = data["student_email"]
    status = data["status"]

    mongo.db.od_requests.update_one({"student_email": email}, {"$set": {"status": status}})
    student = mongo.db.users.find_one({"email": email})
    send_email(email, f"OD Request {status}", f"Hi {student['name']}, your OD request has been {status}.")
    return redirect(url_for("teacher_dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)

