import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter and lookup
app.jinja_env.filters["usd"] = usd
app.jinja_env.globals.update(lookup=lookup)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Update shares owned by user
    names = db.execute("SELECT share_name FROM history")
    for name in names:
        if not db.execute("SELECT share_name FROM shares WHERE share_name = ?", name["share_name"]):
            db.execute("INSERT INTO shares (user_id, share_name, shares) VALUES (?, ?, ?)",
                       session["user_id"], name["share_name"], db.execute("SELECT SUM(quantity) FROM history WHERE share_name = ?", name["share_name"])[0]["SUM(quantity)"])

        else:
            db.execute("UPDATE shares SET shares = ? WHERE share_name = ?", db.execute(
                "SELECT SUM(quantity) FROM history WHERE share_name = ?", name["share_name"])[0]["SUM(quantity)"], name["share_name"])

    stocks = db.execute("SELECT * FROM shares")
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    # Add the totals of each movement to make a grand total
    total = 0
    for stock in stocks:
        # Add quantity * price to a variable called total
        total += (lookup(stock["share_name"])["price"] * stock["shares"])
    total += cash[0]["cash"]
    return render_template("index.html", stocks=stocks, total=total, cash=cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")

    else:
        if not lookup(request.form.get("symbol")):
            return apology("stock not found", 400)

        elif not request.form.get("shares").isnumeric():
            return apology("must input a valid number of shares", 400)

        balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        # Ensure user has enough cash
        if balance < (lookup(request.form.get("symbol"))["price"] * int(request.form.get("shares"))):
            return apology("insufficient balance", 400)
        else:
            # Update cash value in database
            balance -= lookup(request.form.get("symbol"))["price"] * int(request.form.get("shares"))
            db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, session["user_id"])

            # Store movement in database
            db.execute("INSERT INTO history (user_id, share_name, quantity, time, price) VALUES (?, ?, ?, ?, ?)",
                       session["user_id"], request.form.get("symbol").upper(), request.form.get("shares"), db.execute("SELECT CURRENT_TIMESTAMP")[0]['CURRENT_TIMESTAMP'], lookup(request.form.get("symbol"))["price"])
            return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    movements = db.execute("SELECT * FROM history")
    return render_template("history.html", movements=movements)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")

    else:
        stock = lookup(request.form.get("symbol"))
        if stock:
            return render_template("quoted.html", stock=stock)
        else:
            return apology("share price not found", 400)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        password = request.form.get("password")

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 400)

        # Ensure password matches confirmation
        elif password != request.form.get("confirmation"):
            return apology("must provide matching passwords", 400)

        # Force user to input a password including letters, numbers and symbols
        count = 0
        for char in password:
            if char.isdigit():
                count += 1
                break

        for char in password:
            if char.isalpha():
                count += 1
                break

        for char in password:
            if not char.isalnum():
                count += 1
                break

        if len(password) < 8 or count != 3:
            return apology("password must contain at least 8 characters including letters, numbers and symbols")

        # Ensure username is not already registered
        if db.execute("SELECT username FROM users WHERE username = ?", request.form.get("username")):
            return apology("username already taken", 400)
        # Add user to database
        else:
            db.execute("INSERT INTO users(username, hash) VALUES (?, ?)", request.form.get("username"),
                       generate_password_hash(request.form.get("password"), method="pbkdf2:sha256", salt_length=8))

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    shares = db.execute("SELECT share_name FROM shares")
    if request.method == "GET":
        return render_template("sell.html", shares=shares)

    else:
        if not db.execute("SELECT share_name FROM shares WHERE share_name = ?", request.form.get("symbol").upper()):
            return apology("must own share", 400)

        quantity = db.execute("SELECT shares FROM shares WHERE share_name = ?", request.form.get("symbol").upper())

        if int(request.form.get("shares")) not in range(1, quantity[0]["shares"] + 1, 1):
            return apology("must own sufficient shares", 400)

        else:
            balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
            # Update cash value in database
            balance += lookup(request.form.get("symbol"))["price"] * int(request.form.get("shares"))
            db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, session["user_id"])

            # Store movement in database
            db.execute("INSERT INTO history (user_id, share_name, quantity, time, price) VALUES (?, ?, ?, ?, ?)",
                       session["user_id"], request.form.get("symbol").upper(), int(request.form.get("shares")) * -1, db.execute("SELECT CURRENT_TIMESTAMP")[0]['CURRENT_TIMESTAMP'], lookup(request.form.get("symbol"))["price"])

            return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)