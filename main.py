from flask import Flask, render_template, url_for, request, redirect, jsonify, flash
from flask_pymongo import PyMongo
from flask_login import (
    LoginManager,
    login_user,
    current_user,
    login_required,
    logout_user,
)
from flask_socketio import SocketIO
from wtf_fields import *
from models import *
import os, time, json, pymongo

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/Quickie"
db = PyMongo(app).db
app.secret_key = "Change later"
login = LoginManager(app)
socketio = SocketIO(app)
login.init_app(app)


@login.user_loader
def load_user(username):
    user_data = db.users.find_one({"username": username})
    if user_data:
        return User(user_data["username"])
    return None


@app.route("/")
def home():
    return redirect(url_for("chat"))


@app.route("/chat")
@app.route("/chat/<chat_name>")
def chat(chat_name=None):
    if current_user.is_authenticated:
        friends = db.users.find_one({"username": current_user.id})["friends"]
        group_ids = db.users.find_one({"username": current_user.id})["groups"]
        groups = []
        for group_id in group_ids:
            groups.append(group_id["name"])
        contacts = friends + groups
        group = False
        messages=False
        if chat_name != None:
            if chat_name in friends:
                name1=f"{current_user.id}_{chat_name}"
                name2=f"{chat_name}_{current_user.id}"
                dbase=db.groups.find_one({"name":name1})
                if dbase:
                    messages=dbase["messages"]
                else:
                    dbase=db.groups.find_one({"name":name2})
                    messages=dbase["messages"]
            elif chat_name in groups:
                spec = next(
                    (item for item in group_ids if item["name"] == chat_name), False
                )
                members = db.groups.find_one({"_id": spec["id"]})["members"]
                group = {"status": True, "members": members}
                messages=db.groups.find_one({"name":chat_name})["messages"]
            else:
                return redirect("/chat")
        return render_template(
            "index.html",
            username=current_user.id,
            friends=friends,
            groups=groups,
            contacts=contacts,
            chat_name=chat_name,
            group=group,
            messages=messages
        )
    else:
        flash("Please Log in.", "danger")
        return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_anonymous:
        log_form = LoginForm()
        if log_form.validate_on_submit():
            user_data = db.users.find_one({"username": log_form.username.data})
            user = User(user_data["username"])
            login_user(user)
            return redirect(url_for("chat"))
        return render_template("login.html", form=log_form)
    else:
        return redirect(url_for("chat"))


@login_required
@app.route("/logout", methods=["GET"])
def logout():
    logout_user()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_anonymous:
        reg_form = RegistrationForm()
        if reg_form.validate_on_submit():
            username = reg_form.username.data
            password = reg_form.password.data
            email = reg_form.email.data
            h_pass = pbkdf2_sha256.hash(password)
            user = {
                "username": username,
                "email": email,
                "password": h_pass,
                "friends": [],
                "groups": [],
            }
            db.users.insert_one(user)
            flash("Registered Successfully Please login.", "success")
            return redirect(url_for("login"))
        return render_template("register.html", form=reg_form)
    else:
        return redirect(url_for("chat"))


@login_required
@app.route("/create_group", methods=["POST"])
def create_group():
    name = request.json["data"]["group_name"]
    exist = db.users.find_one({"username": name})
    if not exist:
        creator = current_user.id
        members = [creator]
        lis = request.json["data"]
        for key in lis:
            if key != "group_name":
                members.append(lis[key])
        already_existing_groups = db.groups.find({"name": name})
        for group in already_existing_groups:
            members_in = group["members"]
            if current_user.id in members_in:
                return jsonify(
                    {
                        "status": "failure",
                        "message": f"You are already in group named {name}",
                    }
                )
        done = db.groups.insert_one(
            {"name": name, "creator": creator, "members": members, "messages": []}
        )
        for username in members:
            filter = {"username": username}
            update = {"$push": {"groups": {"id": done.inserted_id, "name": name}}}
            db.users.update_one(filter, update)
        return jsonify({"status": "success", "group": name})
    else:
        return jsonify(
            {"status": "failure", "message": "Group name matching with username"}
        )


@login_required
@app.route("/add_friend", methods=["POST"])
def add_friend():
    friend_username = request.json["username"]
    if friend_username != current_user.id:
        friend = db.users.find_one({"username": friend_username})
        if friend:
            user_self = db.users.find_one({"username": current_user.id})
            if friend_username not in user_self["friends"]:
                db.users.update_one(
                    {"username": current_user.id},
                    {"$push": {"friends": friend_username}},
                )
                db.users.update_one(
                    {"username": friend_username},
                    {"$push": {"friends": current_user.id}},
                )
                data = {"sender": current_user.id, "reciever": friend_username}
                socketio.emit("added_friend", data)
                db.groups.insert_one(
                    {
                        "name": f"{current_user.id}_{friend_username}",
                        "creator": "admin",
                        "members": [current_user.id, friend_username],
                        "messages": [],
                    }
                )
                return jsonify(
                    {
                        "status": "success",
                        "message": "Friend added successfully",
                        "friend": friend_username,
                    }
                )
            else:
                return jsonify(
                    {
                        "status": "failure",
                        "message": f"{friend_username} is already your friend",
                    }
                )
        else:
            return jsonify({"status": "failure", "message": "friend doesn't exist"})
    else:
        return jsonify(
            {"status": "failure", "message": "You can't be friends with yourself"}
        )

@socketio.on("send_file")
def handle_send_file(data):
    file_name = data["file_name"]
    file = data["file"]
    with open(f"static/files/{file_name}", "wb") as f:
        f.write(file)
    done = db.messages.insert_one(
        {
            "message": file_name,
            "sender": data["sender"],
            "file":True,
            "reciever": data["reciever"],
            "time": data["time"],
        }
    )
    if data["group"]:
        filter={"name":data["reciever"]}
        update={"$push":{"messages":db.messages.find_one({"_id":done.inserted_id})}}
        db.groups.update_one(filter,update)
        notify_data={"message":"Photo","group":True,"group_name":data["reciever"],"recievers":db.groups.find_one({"name":data["reciever"]})["members"],"sender":data["sender"]}
        socketio.emit("notify",notify_data)
    else:
        name1=f"{data["sender"]}_{data["reciever"]}"
        name2=f"{data["reciever"]}_{data["sender"]}"
        dbase=db.groups.find_one({"name":name1})
        if dbase:
            filter={"name":dbase["name"]}
            update={"$push":{"messages":db.messages.find_one({"_id":done.inserted_id})}}
            db.groups.update_one(filter,update)
        else:
            dbase=db.groups.find_one({"name":name2})
            filter={"name":dbase["name"]}
            update={"$push":{"messages":db.messages.find_one({"_id":done.inserted_id})}}
            db.groups.update_one(filter,update)
        notify_data={"message":"Photo","group":False,"reciever":data["reciever"],"sender":data["sender"]}
        socketio.emit("notify",notify_data)
    new_data={"sender":data["sender"],"file_name":data["file_name"],"time":data["time"],"group":data["group"],"reciever":data["reciever"]}
    socketio.emit("recieve_file", new_data)

@socketio.on("send_message")
def handle_send_message_event(data):
    done = db.messages.insert_one(
        {
            "message": data["message"],
            "sender": data["sender"],
            "file":False,
            "reciever": data["reciever"],
            "time": data["time"],
        }
    )
    if data["group"]:
        filter={"name":data["reciever"]}
        update={"$push":{"messages":db.messages.find_one({"_id":done.inserted_id})}}
        db.groups.update_one(filter,update)
        notify_data={"message":data["message"],"group":True,"group_name":data["reciever"],"recievers":db.groups.find_one({"name":data["reciever"]})["members"],"sender":data["sender"]}
        socketio.emit("notify",notify_data)
    else:
        name1=f"{data["sender"]}_{data["reciever"]}"
        name2=f"{data["reciever"]}_{data["sender"]}"
        dbase=db.groups.find_one({"name":name1})
        if dbase:
            filter={"name":dbase["name"]}
            update={"$push":{"messages":db.messages.find_one({"_id":done.inserted_id})}}
            db.groups.update_one(filter,update)
        else:
            dbase=db.groups.find_one({"name":name2})
            filter={"name":dbase["name"]}
            update={"$push":{"messages":db.messages.find_one({"_id":done.inserted_id})}}
            db.groups.update_one(filter,update)
        notify_data={"message":data["message"],"group":False,"reciever":data["reciever"],"sender":data["sender"]}
        socketio.emit("notify",notify_data)

    socketio.emit("recieve_message", data)


if __name__ == "__main__":
    socketio.run(app, debug=True)
