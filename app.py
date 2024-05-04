import os

from cs50 import SQL
from flask import Flask, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response



@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    id = session["user_id"]
    update()
    stocks = db.execute("SELECT symbol, shares AS shares, price AS price FROM stocks WHERE person_id = ? GROUP BY symbol", id)
    cash = db.execute("SELECT cash FROM users WHERE id = ?", id)[0]["cash"]

    return render_template("index.html", stocks=stocks, cash=cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    
    symbol = request.form.get("symbol").upper()
    boughtShares = request.form.get("shares")

    if symbol:
        company = lookup(symbol)

    if not symbol or not company or boughtShares.isalpha():
        return apology("Invalid Company")
    
    boughtShares = int(boughtShares)
    
    try:
        boughtShares
        if boughtShares < 1:
            return apology("Invalid Number of Shares")
    except ValueError:
        return apology("Invalid Number of Shares")

    id = session["user_id"]
    cash =  int(db.execute("SELECT cash FROM users WHERE id = ?", id)[0]["cash"])
    buyValue = boughtShares * float(company["price"])

    if cash > buyValue:
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash - buyValue, id)
        stocks = db.execute("SELECT shares FROM stocks WHERE person_id = ? AND symbol = ?", id, symbol)
        db.execute("INSERT INTO history (person_id, symbol, shares, price) VALUES(?, ?, ?, ?)", id, symbol, boughtShares, -1 * float(company["price"]))
        if stocks != []:
            stocks = stocks[0]["shares"]
            db.execute("UPDATE stocks SET shares = ? WHERE person_id = ? AND symbol = ?", stocks + boughtShares, id, symbol)
        else:
            db.execute("INSERT INTO stocks (person_id, symbol, shares) VALUES(?, ?, ?)", id, symbol, boughtShares)
        return redirect("/")
    else:
        return apology("Not Enough Cash")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    id = session["user_id"]
    stocks = db.execute("SELECT symbol, shares, price FROM history WHERE person_id = ?", id)
    stocks.reverse()
    cash = db.execute("SELECT cash FROM users WHERE id = ?", id)[0]["cash"]

    return render_template("history.html", stocks=stocks, cash=cash)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    if request.method == "GET":
        return render_template("login.html")

    # Ensure username was submitted
    if not request.form.get("username"):
        return apology("must provide username", 403)

    # Ensure password was submitted
    elif not request.form.get("password"):
        return apology("must provide password", 403)

    # Query database for username
    rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

    # Ensure username exists and password is correct
    if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
        return apology("invalid username and/or password", 403)

    # Remember which user has logged in
    session["user_id"] = rows[0]["id"]

    # Redirect user to home page
    return redirect("/")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget the user_id
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
        symbol = request.form.get("symbol").upper()
        if symbol:
            company = lookup(symbol)
            if company:
                return render_template("quoted.html", company=company)

        return apology("Invalid Company")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    
    username = request.form.get("username")
    if not username:
        return apology("Invalid Username")

    password = request.form.get("password")
    if not password:
        return apology("Invalid Password")

    confirmedPassword = request.form.get("confirmation")

    if not password == confirmedPassword:
        return apology("Password Do Not Match")

    usernames = db.execute("SELECT username FROM users")

    for name in usernames:
        if name["username"] == username:
            return apology("Username Taken")

    passwordHashed = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
    db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, passwordHashed)
    return render_template("login.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    id = session["user_id"]
    if request.method == "GET":
        stocks = db.execute("SELECT DISTINCT(symbol) FROM stocks WHERE person_id = ?", id)
        return render_template("sell.html", stocks=stocks)
    
    symbol = request.form.get("symbol").upper()
    soldShares = request.form.get("shares")
    
    if symbol:
        company = lookup(symbol)

    if not company or not symbol:
        return apology("Invalid Company")
    if not soldShares or soldShares.isalpha():
        return apology("Invalid Number of Shares")
    
    soldShares = int(soldShares)

    if soldShares < 1:
        return apology("Invalid Number of Shares")

    total = db.execute("SELECT shares FROM stocks WHERE person_id = ? AND symbol = ?", id, symbol)[0]["shares"]

    if not soldShares <= total:
        return apology("Not Enough Shares")

    cash = db.execute("SELECT cash FROM users WHERE id = ?", id)[0]["cash"]
    
    sellValue = soldShares * float(company["price"])

    db.execute("INSERT INTO history (person_id, symbol, shares, price) VALUES(?, ?, ?, ?)", id, symbol, soldShares, float(company["price"]))

    db.execute("UPDATE stocks SET shares = ? WHERE person_id = ? AND symbol = ?", total - soldShares, id, symbol)
    
    db.execute("UPDATE users SET cash = ? WHERE id = ?", cash + sellValue, id)

    return redirect("/")
    
def update():
    id = session["user_id"]
    stocks = db.execute("SELECT symbol, shares AS shares, price AS price FROM stocks WHERE person_id = ? GROUP BY symbol", id)

    for stock in stocks:
        company = lookup(stock["symbol"])
        db.execute("UPDATE stocks SET price = ? WHERE person_id = ? AND symbol = ?", float(company["price"]), id, stock["symbol"])