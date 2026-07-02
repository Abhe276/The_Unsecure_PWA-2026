from flask import Flask, session
from flask_wtf.csrf import CSRFProtect
import os
from flask import render_template
from flask import request
from flask import redirect
from flask_cors import CORS
import user_management as dbHandler


#The url parameter was passed directly to redirect() with no validation. An attacker could craft a url and send it users to a malicious site using the legitimate PWA domain as cover.
#FIX = Whitelist of permitted internal redirect destinations.
ALLOWED_REDIRECTS = ['/', '/index.html', '/signup.html', '/success.html']

# Code snippet for logging a message
# app.logger.critical("message")

app = Flask(__name__)
app.jinja_env.auto_reload = True
app.config['TEMPLATES_AUTO_RELOAD'] = True 
#No CSRF protection. An attacker on another domain could build a hidden form that submitted to this app using a logged-in ser's session without their knowledge
#FIX = Added secret key and CSRF protection
#CSRFProtect generates a unique token for each session that must match every form submission
app.secret_key = os.urandom(24)
csrf = CSRFProtect(app)

#With no X-Frame-Options or CSP header, this site could be embedded inside an invisible iframe on a malicious page
#FIX = Add security headers to prevent clickjacking
@app.after_request
def set_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "frame-ancestors 'none'"
    return response

# Enable CORS to allow cross-origin requests (needed for CSRF demo in Codespaces)


#CORS(app) with no arguments allows requests from ANY origin
#FIX = restrict CORS to trusted origins only
CORS(app, origins=["http://127.0.0.1:5000", "http://localhost:5000"])


@app.route("/success.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def addFeedback():
    #FIX = Protect this route by checking for a valid session
    #If no session exists the user is rediected back to login page
    if 'user' not in session:
        return redirect('/')
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        #Any external or unlisted URL defaults to home page instead of actually redirecting to unauthorised pages
        #FIX=Only allow redirects to whitelisted internal paths
        if url not in ALLOWED_REDIRECTS:
            url = "/"
        return redirect(url, code=302)
    if request.method == "POST":
        feedback = request.form["feedback"]
        dbHandler.insertFeedback(feedback)
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value=session['user'])
    else:
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value=session['user'])


@app.route("/signup.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def signup():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        #Any external or unlisted URL defaults to home page instead of actually redirecting to unauthorised pages
        #FIX=Only allow redirects to whitelisted internal paths
        if url not in ALLOWED_REDIRECTS:
            url = "/"
        return redirect(url, code=302)
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        DoB = request.form["dob"]
        dbHandler.insertUser(username, password, DoB)
        return render_template("/index.html")
    else:
        return render_template("/signup.html")


@app.route("/index.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
@app.route("/", methods=["POST", "GET"])
def home():
    # Simple Dynamic menu
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        #Any external or unlisted URL defaults to home page instead of actually redirecting to unauthorised pages
        #FIX=Only allow redirects to whitelisted internal paths
        if url not in ALLOWED_REDIRECTS:
            url = "/"
        return redirect(url, code=302)
    # Pass message to front end
    elif request.method == "GET":
        msg = request.args.get("msg", "")
        return render_template("/index.html", msg=msg)
    elif request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        isLoggedIn = dbHandler.retrieveUsers(username, password)
        if isLoggedIn:
            # No session was created after login, The success page is loaded for anyone who navigated to it directly without logging in.
            # FIX = Store authenticated user in server side session
            #Storing the user in session allows protected routes to verify authentication before providing with content
            session['user'] = username
            dbHandler.listFeedback()
            return render_template("/success.html", value=username, state=isLoggedIn)
        else:
            return render_template("/index.html")
    else:
        return render_template("/index.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")
#Previously the logout link redirected to home without destroying the session
#FIX = Proper logout clears the server side session entirely


if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    #debug=True caused Flask to display full stack traces giving attackers everything about application internals
    #FIX= Disabled debug mode


    app.run(debug=False, host="0.0.0.0", port=5000)
