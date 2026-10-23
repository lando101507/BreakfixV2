import os
import secrets
import hashlib
import requests

from datetime import datetime, timedelta, timezone

from flask import Flask, render_template, request, redirect, session, url_for
from flask_mail import Mail, Message
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from config.supabase_config import supabase


load_dotenv()

app = Flask(__name__)

app.config.update(
    SECRET_KEY=os.getenv("FLASK_SECRET_KEY"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
    ),
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

if not app.config["SECRET_KEY"]:
    raise ValueError("FLASK_SECRET_KEY is missing")

app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", "587"))
app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS", "True").lower() == "true"
app.config["MAIL_USE_SSL"] = os.getenv("MAIL_USE_SSL", "False").lower() == "true"
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_DEFAULT_SENDER")

mail = Mail(app)

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from flask import url_for
from flask_mail import Message


def hash_reset_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# =========================
# FORGOT PASSWORD
# =========================


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "GET":
        return render_template("forgot-password.html")

    email = request.form.get("email", "").strip().lower()

    if not email:
        return render_template(
            "forgot-password.html",
            error="Please enter your email."
        )

    try:
        # Find the registered user
        result = (
            supabase.table("users")
            .select("id,email")
            .eq("email", email)
            .limit(1)
            .execute()
        )

        success_message = (
            "If that email is registered, a password reset link "
            "will be sent."
        )

        # Keep the same generic message if the email is not registered
        if not result.data:
            return render_template(
                "forgot-password.html",
                success=success_message
            )

        user = result.data[0]

                # Check email settings
        if not app.config.get("MAIL_USERNAME"):
            raise ValueError("MAIL_USERNAME is missing in .env")

        if not app.config.get("MAIL_PASSWORD"):
            raise ValueError("MAIL_PASSWORD is missing in .env")

        # Generate a secure reset token
        token = secrets.token_urlsafe(32)
        token_hash = hash_reset_token(token)

        expires_at = (
            datetime.now(timezone.utc)
            + timedelta(minutes=30)
        ).isoformat()

        # Save the hashed token in Supabase
        supabase.table("password_reset_tokens").insert({
            "user_id": user["id"],
            "token_hash": token_hash,
            "expires_at": expires_at,
            "used": False
        }).execute()

        # Build the reset link
        reset_url = url_for(
        "reset_password",
         token=token,
         _external=True
        )

        # Create the email
        message = Message(
            subject="BreakFix Password Reset",
            sender=("BreakFix System", app.config["MAIL_DEFAULT_SENDER"]),
            recipients=[user["email"]]
        )

        message.body = (
            "Hello,\n\n"
            "We received a request to reset your BreakFix password.\n\n"
            "Click this link within 30 minutes:\n\n"
            f"{reset_url}\n\n"
            "If you did not request this, you can ignore this email."
        )

        # IMPORTANT: Actually send the email
        send_reset_email(email, reset_url)

        app.logger.info("Password reset email sent successfully.")

        return render_template(
            "forgot-password.html",
            success=success_message
        )

    except Exception:
        app.logger.exception("Forgot password request failed")

        return render_template(
            "forgot-password.html",
            error=(
                "Unable to send the reset email. "
                "Please check the Flask Terminal."
            )
        )


# =========================
# RESET PASSWORD
# =========================

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):

    token_hash = hash_reset_token(token)

    try:
        result = (
            supabase.table("password_reset_tokens")
            .select("id,user_id,expires_at,used")
            .eq("token_hash", token_hash)
            .eq("used", False)
            .limit(1)
            .execute()
        )

        if not result.data:
            return (
                "This reset link is invalid or has already been used.",
                400
            )

        reset_record = result.data[0]

        expires_at = datetime.fromisoformat(
            reset_record["expires_at"].replace("Z", "+00:00")
        )

        if datetime.now(timezone.utc) >= expires_at:
            return (
                "This reset link has expired. Please request a new one.",
                400
            )

        if request.method == "GET":
            return render_template(
                "reset-password.html",
                token=token
            )

        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(password) < 8:
            return render_template(
                "reset-password.html",
                token=token,
                error="Password must be at least 8 characters."
            )

        if password != confirm_password:
            return render_template(
                "reset-password.html",
                token=token,
                error="Passwords do not match."
            )

        # Save the new password using the same hashing method as login.
        supabase.table("users").update({
            "password": generate_password_hash(password)
        }).eq("id", reset_record["user_id"]).execute()

        # Mark this token as used.
        supabase.table("password_reset_tokens").update({
            "used": True
        }).eq("id", reset_record["id"]).execute()

        return render_template(
            "reset-password.html",
            success="Password updated! You can now log in.",
            token=None
        )

    except Exception:
        app.logger.exception("Password reset failed")
        return (
            "Unable to reset password. Please check the Flask Terminal.",
            500
        )



# =========================
# LOGIN PAGE
# =========================

@app.route("/")
def landing():
    return render_template("landing.html")


# =========================
# LOGIN
# =========================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    if not email or not password:
        return render_template(
            "login.html",
            error="Please enter your email and password."
        )

    try:
        # Find account in Supabase
        result = (
            supabase
            .table("users")
            .select("id,fullname,email,password,role")
            .eq("email", email)
            .limit(1)
            .execute()
        )

        if not result.data:
            return render_template(
                "login.html",
                error="Account not found. Please check your email."
            )

        user = result.data[0]
        saved_password = user.get("password") or ""

        # Check hashed password
        try:
            password_ok = check_password_hash(
                saved_password, password
            )
        except (ValueError, TypeError):
            password_ok = False

        # Support older plain-text password records
        if not password_ok and saved_password == password:
            password_ok = True

            supabase.table("users").update({
                "password": generate_password_hash(password)
            }).eq("id", user["id"]).execute()

        if not password_ok:
            return render_template(
                "login.html",
                error="Incorrect email or password."
            )

        # Save session
        session.clear()
        session["user_id"] = user["id"]
        session["fullname"] = user.get("fullname") or "User"
        session["role"] = (
            user.get("role") or "employee"
        ).strip().lower()

        # Redirect according to role
        role = session["role"]

        if role == "admin":
            return redirect("/admin-dashboard")

        elif role == "maintenance":
            return redirect("/maintenance-dashboard")

        else:
            return redirect("/dashboard")

    except Exception:
        app.logger.exception("Login failed")

        return render_template(
            "login.html",
            error="Login failed. Please check the Flask Terminal."
        )


# =========================
# REGISTER PAGE
# =========================

@app.route("/register")
def register_page():
    return render_template("register.html")


# =========================
# REGISTER
# =========================

@app.route("/register", methods=["POST"])
def register():

    fullname = request.form.get("fullname", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    # Check required fields
    if not fullname or not email or not password:
        return """
        Please complete all fields.
        <br><br>
        <a href="/register">Back to Register</a>
        """

    # Check if email already exists
    existing = (
        supabase
        .table("users")
        .select("id")
        .eq("email", email)
        .execute()
    )

    if existing.data:
        return """
        Email already registered.
        <br><br>
        <a href="/">Back to Login</a>
        """

    # Create secure password hash
    hashed_password = generate_password_hash(password)

    # Save account to Supabase
    result = (
        supabase
        .table("users")
        .insert({
            "fullname": fullname,
            "email": email,
            "password": hashed_password,
            "role": "employee"
        })
        .execute()
    )

    if not result.data:
        return """
        Registration failed.
        <br><br>
        <a href="/register">Try Again</a>
        """

    return redirect("/")


# =========================
# EMPLOYEE DASHBOARD
# =========================

@app.route("/dashboard")
def dashboard():

    # Check login
    if "user_id" not in session:
        return redirect("/")

    user_id = session["user_id"]

    # Get employee reports
    reports = (
        supabase
        .table("facility_reports")
        .select("id,status")
        .eq("user_id", user_id)
        .execute()
    )

    report_data = reports.data or []

    # Total reports
    total_reports = len(report_data)

    # Counters
    pending_reports = 0
    in_progress_reports = 0
    resolved_reports = 0

    # Count report status
    for report in report_data:

        status = report.get("status")

        if status in [
            "NEW",
            "UNDER REVIEW",
            "ASSIGNED"
        ]:
            pending_reports += 1

        elif status in [
            "IN PROGRESS",
            "WAITING FOR PARTS"
        ]:
            in_progress_reports += 1

        elif status == "RESOLVED":
            resolved_reports += 1

    # Show dashboard
    return render_template(
        "dashboard.html",
        fullname=session["fullname"],
        role=session["role"],
        total_reports=total_reports,
        pending_reports=pending_reports,
        in_progress_reports=in_progress_reports,
        resolved_reports=resolved_reports
    )

# =========================
# REPORT PROBLEM PAGE
# =========================

@app.route("/report-problem")
def report_problem():

    if "user_id" not in session:
        return redirect("/")

    # Get categories from Supabase
    result = (
        supabase
        .table("categories")
        .select("id,name")
        .order("name")
        .execute()
    )

    categories = result.data or []

    return render_template(
        "report-problem.html",
        categories=categories,
        fullname=session["fullname"],
        role=session["role"]
    )


# =========================
# SUBMIT REPORT
# =========================

@app.route("/report-problem", methods=["POST"])
def submit_report():

    if "user_id" not in session:
        return redirect("/")

    user_id = session["user_id"]

    category_id = request.form.get("category_id")
    location = request.form.get("location", "").strip()
    priority = request.form.get("priority", "Medium")
    description = request.form.get("description", "").strip()

    # Check required fields
    if not category_id or not location or not description:
        return """
        Please complete all required fields.
        <br><br>
        <a href="/report-problem">Back to Report Problem</a>
        """

    # Generate report code
    from datetime import datetime

    report_code = "BF-" + datetime.now().strftime("%Y%m%d%H%M%S")

    photo_url = None

    # =========================
    # PHOTO UPLOAD
    # =========================

    photo = request.files.get("photo")

    if photo and photo.filename:

        allowed_extensions = ["jpg", "jpeg", "png", "webp"]

        extension = photo.filename.rsplit(".", 1)[-1].lower()

        if extension not in allowed_extensions:
            return """
            Invalid photo format.
            <br><br>
            Allowed: JPG, JPEG, PNG, WEBP
            <br><br>
            <a href="/report-problem">Back</a>
            """

        # Read image
        file_data = photo.read()

        # Maximum 10MB
        if len(file_data) > 10 * 1024 * 1024:
            return """
            Photo is too large. Maximum size is 10MB.
            <br><br>
            <a href="/report-problem">Back</a>
            """

        file_path = f"reports/{user_id}/{report_code}.{extension}"

        try:

            supabase.storage \
                .from_("breakfix-uploads") \
                .upload(
                    file_path,
                    file_data,
                    {
                        "content-type": photo.content_type,
                        "upsert": "true"
                    }
                )

            photo_url = supabase.storage \
                .from_("breakfix-uploads") \
                .get_public_url(file_path)

        except Exception as e:

            return f"""
            Photo upload failed.
            <br><br>
            Error: {e}
            <br><br>
            <a href="/report-problem">Back</a>
            """

    # =========================
    # SAVE REPORT
    # =========================

    result = (
        supabase
        .table("facility_reports")
        .insert({
            "report_code": report_code,
            "user_id": user_id,
            "category_id": int(category_id),
            "location": location,
            "description": description,
            "priority": priority,
            "photo": photo_url,
            "status": "NEW"
        })
        .execute()
    )

    if not result.data:

        return """
        Failed to submit report.
        <br><br>
        <a href="/report-problem">Try Again</a>
        """

    return redirect("/my-reports")

# =========================
# MY REPORTS
# =========================

@app.route("/my-reports")
def my_reports():

    if "user_id" not in session:
        return redirect("/")

    user_id = session["user_id"]

    try:
        # Get reports first
        result = (
            supabase
            .table("facility_reports")
            .select(
                "id,report_code,category_id,location,description,"
                "priority,status,photo,repair_notes,created_at"
            )
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .execute()
        )

        reports = result.data or []

        # Get category names separately
        categories_result = (
            supabase
            .table("categories")
            .select("id,name")
            .execute()
        )

        categories = categories_result.data or []
        category_map = {c["id"]: c["name"] for c in categories}

        # Keep the same structure expected by my-reports.html
        for report in reports:
            report["categories"] = {
                "name": category_map.get(report.get("category_id"), "Other")
            }

        return render_template(
            "my-reports.html",
            fullname=session["fullname"],
            role=session["role"],
            reports=reports
        )

    except Exception as e:
        return f"""
        <h2>Unable to load My Reports</h2>
        <p>Error: {e}</p>
        <br>
        <a href="/dashboard">Back to Dashboard</a>
        """


# =========================
# LOST & FOUND
# =========================

@app.route("/lost-found", methods=["GET", "POST"])
def lost_found():

    if "user_id" not in session:
        return redirect("/")

    if request.method == "POST":

        item_type = request.form.get("item_type", "").strip()
        item_name = request.form.get("item_name", "").strip()
        category = request.form.get("category", "").strip()
        location = request.form.get("location", "").strip()
        description = request.form.get("description", "").strip()

        if item_type not in ["LOST", "FOUND"]:
            return "Invalid item type. <a href='/lost-found'>Back</a>"

        if not item_name or not category or not location or not description:
            return """
            Please complete all required fields.
            <br><br>
            <a href="/lost-found">Back to Lost & Found</a>
            """

        from datetime import datetime

        report_code = "LF-" + datetime.now().strftime("%Y%m%d%H%M%S")

        try:
            result = supabase.table("lost_found_items").insert({
                "report_code": report_code,
                "user_id": session["user_id"],
                "item_type": item_type,
                "item_name": item_name,
                "category": category,
                "location": location,
                "description": description,
                "status": item_type
            }).execute()

            if not result.data:
                return """
                Failed to save item.
                <br><br>
                <a href="/lost-found">Try Again</a>
                """

            return redirect("/my-items")

        except Exception as e:
            return f"""
            <h2>Unable to save Lost & Found item</h2>
            <p>Error: {e}</p>
            <br>
            <a href="/lost-found">Back</a>
            """

    return render_template(
        "lost-found.html",
        fullname=session["fullname"],
        role=session["role"]
    )


# =========================
# MY ITEMS
# =========================

@app.route("/my-items")
def my_items():

    if "user_id" not in session:
        return redirect("/")

    user_id = session["user_id"]

    try:
        result = (
            supabase
            .table("lost_found_items")
            .select(
                "id,report_code,item_type,item_name,category,"
                "location,description,photo,status,created_at"
            )
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .execute()
        )

        items = result.data or []

        return render_template(
            "my-items.html",
            fullname=session["fullname"],
            role=session["role"],
            items=items
        )

    except Exception as e:
        return f"""
        <h2>Unable to load My Items</h2>
        <p>Error: {e}</p>
        <br>
        <a href="/dashboard">Back to Dashboard</a>
        """

    
# =========================
# EDIT MY ITEM
# =========================

@app.route("/my-items/<item_id>/edit", methods=["POST"])
def edit_my_item(item_id):

    if "user_id" not in session:
        return redirect("/")

    user_id = session["user_id"]

    item_name = request.form.get("item_name", "").strip()
    category = request.form.get("category", "").strip()
    location = request.form.get("location", "").strip()
    description = request.form.get("description", "").strip()

    if not all([item_name, category, location, description]):
        return redirect("/my-items")

    try:
        # Only edit the current user's active LOST/FOUND item
        existing = (
            supabase.table("lost_found_items")
            .select("id")
            .eq("id", item_id)
            .eq("user_id", user_id)
            .in_("status", ["LOST", "FOUND"])
            .execute()
        )

        if not existing.data:
            return "Item not found or cannot be edited.", 404

        supabase.table("lost_found_items").update({
            "item_name": item_name,
            "category": category,
            "location": location,
            "description": description
        }).eq("id", item_id).eq(
            "user_id", user_id
        ).execute()

        return redirect("/my-items")

    except Exception as e:
        app.logger.exception("Unable to edit Lost & Found item")
        return "Unable to update item. Please try again.", 500


# =========================
# CANCEL MY ITEM
# =========================

@app.route("/my-items/<item_id>/cancel", methods=["POST"])
def cancel_my_item(item_id):

    if "user_id" not in session:
        return redirect("/")

    user_id = session["user_id"]

    try:
        # Only cancel the current user's active LOST/FOUND item
        existing = (
            supabase.table("lost_found_items")
            .select("id")
            .eq("id", item_id)
            .eq("user_id", user_id)
            .in_("status", ["LOST", "FOUND"])
            .execute()
        )

        if not existing.data:
            return "Item not found or cannot be cancelled.", 404

        supabase.table("lost_found_items").update({
            "status": "CANCELLED"
        }).eq(
            "id", item_id
        ).eq(
            "user_id", user_id
        ).execute()

        return redirect("/my-items")

    except Exception:
        app.logger.exception("Unable to cancel Lost & Found item")
        return "Unable to cancel item. Please try again.", 500


# =========================
# ADMIN DASHBOARD
# =========================

@app.route("/admin-dashboard")
def admin_dashboard():

    if "user_id" not in session:
        return redirect("/")

    if session.get("role") != "admin":
        return redirect("/dashboard")

    try:
        # Get all facility reports
        reports_result = (
            supabase
            .table("facility_reports")
            .select("*")
            .order("created_at", desc=True)
            .execute()
        )

        reports = reports_result.data or []

        # Get users
        users_result = (
            supabase
            .table("users")
            .select("id,fullname,email,role")
            .execute()
        )

        users = users_result.data or []
        user_map = {str(u["id"]): u for u in users}

        # Get categories
        categories_result = (
            supabase
            .table("categories")
            .select("id,name")
            .execute()
        )

        categories = categories_result.data or []
        category_map = {
            str(c["id"]): c["name"] for c in categories
        }

        # Add reporter, maintenance, and category names
        for report in reports:
            reporter = user_map.get(
                str(report.get("user_id")), {}
            )

            assigned = user_map.get(
                str(report.get("assigned_to")), {}
            )

            report["reporter_name"] = reporter.get(
                "fullname", "Unknown"
            )

            report["assigned_name"] = assigned.get(
                "fullname", "Not assigned"
            )

            report["category_name"] = category_map.get(
                str(report.get("category_id")), "Other"
            )

            

        # Maintenance users only
        maintenance_users = [
            u for u in users
            if u.get("role") == "maintenance"
        ]

        # Lost & Found items
        lost_result = (
            supabase
            .table("lost_found_items")
            .select("id,status")
            .execute()
        )

        lost_items = lost_result.data or []

        # Facility report statistics
        total_reports = len(reports)

        new_reports = sum(
            1 for r in reports
            if r.get("status") in ["NEW", "UNDER REVIEW"]
        )

        assigned_reports = sum(
            1 for r in reports
            if r.get("status") == "ASSIGNED"
        )

        in_progress_reports = sum(
            1 for r in reports
            if r.get("status") in [
                "IN PROGRESS", "WAITING FOR PARTS"
            ]
        )

        resolved_reports = sum(
            1 for r in reports
            if r.get("status") == "RESOLVED"
        )

        return render_template(
            "admin-dashboard.html",
            fullname=session.get("fullname", "Admin"),
            reports=reports,
            maintenance_users=maintenance_users,
            total_reports=total_reports,
            new_reports=new_reports,
            assigned_reports=assigned_reports,
            in_progress_reports=in_progress_reports,
            resolved_reports=resolved_reports,
            total_lost_found=len(lost_items)
        )

    except Exception as e:
        return f"""
        <h2>Unable to load Admin Dashboard</h2>
        <p>{e}</p>
        <a href="/admin-dashboard">Try Again</a>
        """


# =========================
# ASSIGN MAINTENANCE STAFF
# =========================

@app.route("/admin/assign-maintenance", methods=["POST"])
def assign_maintenance():

    if "user_id" not in session:
        return redirect("/")

    if session.get("role") != "admin":
        return redirect("/dashboard")

    report_id = request.form.get("report_id")
    maintenance_id = request.form.get("maintenance_id")

    if not report_id or not maintenance_id:
        return redirect("/admin-dashboard")

    try:
        # Confirm the selected user is maintenance staff
        staff_result = (
            supabase
            .table("users")
            .select("id")
            .eq("id", maintenance_id)
            .eq("role", "maintenance")
            .execute()
        )

        if not staff_result.data:
            return "Invalid maintenance staff. <a href='/admin-dashboard'>Back</a>"

        (
            supabase
            .table("facility_reports")
            .update({
                "assigned_to": maintenance_id,
                "status": "ASSIGNED"
            })
            .eq("id", report_id)
            .execute()
        )

        return redirect("/admin-dashboard")

    except Exception as e:
        return f"""
        <h2>Unable to assign maintenance staff</h2>
        <p>{e}</p>
        <a href="/admin-dashboard">Back to Admin Dashboard</a>
        """


# =========================
# UPDATE REPORT STATUS
# =========================

@app.route("/admin/update-status", methods=["POST"])
def admin_update_status():

    if "user_id" not in session:
        return redirect("/")

    if session.get("role") != "admin":
        return redirect("/dashboard")

    report_id = request.form.get("report_id")
    status = request.form.get("status")

    allowed_statuses = [
        "NEW",
        "UNDER REVIEW",
        "ASSIGNED",
        "IN PROGRESS",
        "WAITING FOR PARTS",
        "RESOLVED",
        "CANCELLED"
    ]

    if not report_id or status not in allowed_statuses:
        return redirect("/admin-dashboard")

    try:
        (
            supabase
            .table("facility_reports")
            .update({"status": status})
            .eq("id", report_id)
            .execute()
        )

        return redirect("/admin-dashboard")

    except Exception as e:
        return f"""
        <h2>Unable to update report status</h2>
        <p>{e}</p>
        <a href="/admin-dashboard">Back to Admin Dashboard</a>
        """

# =========================
# ADMIN FACILITY REPORTS
# =========================


@app.route("/admin/facility-reports")
def admin_facility_reports():
    if "user_id" not in session:
        return redirect("/")

    if session.get("role") != "admin":
        return redirect("/dashboard")

    try:
        # 1. Get all facility reports
        reports_result = (
            supabase.table("facility_reports")
            .select("*")
            .order("created_at", desc=True)
            .execute()
        )
        reports = reports_result.data or []

        # 2. Get employee and maintenance accounts
        users_result = (
            supabase.table("users")
            .select("id,fullname,email,role")
            .execute()
        )
        users = users_result.data or []

        # Match user IDs consistently
        user_map = {
            str(user.get("id")): user
            for user in users
        }

        # 3. Get category names
        categories_result = (
            supabase.table("categories")
            .select("id,name")
            .execute()
        )
        categories = categories_result.data or []

        category_map = {
            str(category.get("id")): category.get("name", "Other")
            for category in categories
        }

        # 4. Attach employee, category, and assigned staff names
        for report in reports:
            reporter = user_map.get(str(report.get("user_id")), {})
            assigned = user_map.get(str(report.get("assigned_to")), {})

            report["reporter_name"] = reporter.get(
                "fullname", "Unknown Employee"
            )

            report["assigned_name"] = assigned.get(
                "fullname", "Not assigned"
            )

            report["category_name"] = category_map.get(
                str(report.get("category_id")), "Other"
            )

        # 5. Only accounts with role = maintenance
        maintenance_users = [
            user for user in users
            if str(user.get("role", "")).strip().lower() == "maintenance"
        ]

        return render_template(
            "admin-facility-reports.html",
            fullname=session.get("fullname", "Admin"),
            reports=reports,
            maintenance_users=maintenance_users
        )

    except Exception as e:
        return f"""
        <h2>Unable to load facility reports</h2>
        <p>{e}</p>
        <a href="/admin-dashboard">Back to Dashboard</a>
        """


# =========================
# ADMIN LOST & FOUND
# =========================

@app.route("/admin/lost-found", methods=["GET"])
def admin_lost_found():
    if "user_id" not in session:
        return redirect("/login")

    if session.get("role") != "admin":
        return redirect("/login")

    try:
        # Get all Lost & Found reports
        result = (
            supabase.table("lost_found_items")
            .select("*")
            .order("created_at", desc=True)
            .execute()
        )
        items = result.data or []

        # Get users so reporter names and emails are accurate
        users_result = (
            supabase.table("users")
            .select("id,fullname,email")
            .execute()
        )
        users = users_result.data or []

        user_map = {
            str(user.get("id")): user
            for user in users
        }

        # Match each item to its actual reporter
        for item in items:
            user = user_map.get(str(item.get("user_id")), {})

            item["reporter_name"] = (
                user.get("fullname") or "Unknown Employee"
            )
            item["reporter_email"] = user.get("email") or ""

            # Normalize values for consistent display and counting
            item["item_type"] = (
                item.get("item_type") or "LOST"
            ).strip().upper()

            item["status"] = (
                item.get("status") or item["item_type"]
            ).strip().upper()

        return render_template(
            "admin-lost-found.html",
            items=items,
            fullname=session.get("fullname", "Admin"),
            updated=request.args.get("updated") == "1"
        )

    except Exception as e:
        app.logger.exception("Failed to load Admin Lost & Found")
        return f"""
            <h2>Unable to load Lost &amp; Found</h2>
            <p>{e}</p>
            <a href="/admin-dashboard">Back to Dashboard</a>
        """, 500



# =========================
# UPDATE LOST & FOUND STATUS
# =========================

@app.route("/admin/lost-found/update-status", methods=["POST"])
def admin_update_lost_found_status():

    if "user_id" not in session:
        return redirect("/login")

    if session.get("role") != "admin":
        return redirect("/login")

    item_id = request.form.get("item_id", "").strip()
    status = request.form.get("status", "").strip().upper()

    allowed_statuses = [
        "LOST",
        "FOUND",
        "CLAIMED",
        "CANCELLED"
    ]

    if not item_id or status not in allowed_statuses:
        return redirect("/admin/lost-found?error=Invalid+item+or+status")

    try:
        # Check if the item exists
        check_result = (
            supabase.table("lost_found_items")
            .select("id")
            .eq("id", item_id)
            .limit(1)
            .execute()
        )

        if not check_result.data:
            return redirect("/admin/lost-found?error=Item+not+found")

        # Save the new status to Supabase
        supabase.table("lost_found_items").update({
            "status": status
        }).eq("id", item_id).execute()

        # Reload the page using the latest database data
        return redirect("/admin/lost-found?updated=1")

    except Exception:
        app.logger.exception("Failed to update Lost & Found status")
        return redirect("/admin/lost-found?error=Update+failed.+Check+Flask+Terminal")



# =========================
# UPDATE MAINTENANCE REPORT
# =========================

@app.route("/maintenance/update-report", methods=["POST"])
def maintenance_update_report():
    if "user_id" not in session:
        return redirect("/")

    if session.get("role") != "maintenance":
        return redirect("/dashboard")

    report_id = request.form.get("report_id")
    status = request.form.get("status")
    repair_notes = request.form.get("repair_notes", "").strip()

    allowed_statuses = [
        "ASSIGNED",
        "IN PROGRESS",
        "WAITING FOR PARTS",
        "RESOLVED"
    ]

    if not report_id or status not in allowed_statuses:
        return redirect("/maintenance-dashboard")

    try:
        # Check that this report is assigned to the logged-in staff
        result = (
            supabase.table("facility_reports")
            .select("id")
            .eq("id", report_id)
            .eq("assigned_to", session["user_id"])
            .execute()
        )

        if not result.data:
            return "Report not found or not assigned to your account."

        (
            supabase.table("facility_reports")
            .update({
                "status": status,
                "repair_notes": repair_notes
            })
            .eq("id", report_id)
            .eq("assigned_to", session["user_id"])
            .execute()
        )

        return redirect("/maintenance-dashboard")

    except Exception as e:
        return f"""
        <h2>Unable to update report</h2>
        <p>{e}</p>
        <a href="/maintenance-dashboard">Back to Dashboard</a>
        """


# =========================
# MAINTENANCE DASHBOARD
# =========================

@app.route("/maintenance-dashboard", methods=["GET"])
def maintenance_dashboard():

    if "user_id" not in session:
        return redirect("/login")

    if session.get("role") != "maintenance":
        if session.get("role") == "admin":
            return redirect("/admin-dashboard")
        return redirect("/dashboard")

    try:
        result = (
            supabase.table("facility_reports")
            .select("*")
            .eq("assigned_to", session["user_id"])
            .order("created_at", desc=True)
            .execute()
        )

        reports = result.data or []

        total_reports = len(reports)

        assigned_reports = sum(
            1 for report in reports
            if report.get("status") == "ASSIGNED"
        )

        in_progress_reports = sum(
            1 for report in reports
            if report.get("status") in [
                "IN PROGRESS",
                "WAITING FOR PARTS"
            ]
        )

        resolved_reports = sum(
            1 for report in reports
            if report.get("status") == "RESOLVED"
        )

        return render_template(
            "maintenance-dashboard.html",
            fullname=session.get("fullname", "Maintenance"),
            reports=reports,
            total_reports=total_reports,
            assigned_reports=assigned_reports,
            in_progress_reports=in_progress_reports,
            resolved_reports=resolved_reports
        )

    except Exception as e:
        app.logger.exception("Maintenance dashboard failed")
        return f"""
        <h2>Unable to load Maintenance Dashboard</h2>
        <p>{e}</p>
        <a href="/maintenance-dashboard">Try Again</a>
        """

# =========================
# MAINTENANCE ASSIGNED REPORTS
# =========================

@app.route("/maintenance-assigned")
def maintenance_assigned():

    if "user_id" not in session:
        return redirect("/login")

    if session.get("role") != "maintenance":
        if session.get("role") == "admin":
            return redirect("/admin-dashboard")
        return redirect("/dashboard")

    try:
        result = (
            supabase.table("facility_reports")
            .select("*")
            .eq("assigned_to", session["user_id"])
            .neq("status", "RESOLVED")
            .order("created_at", desc=True)
            .execute()
        )

        reports = result.data or []

        return render_template(
            "maintenance-assigned.html",
            fullname=session.get("fullname", "Maintenance"),
            reports=reports
        )

    except Exception as e:
        app.logger.exception("Failed to load assigned reports")
        return f"""
        <h2>Unable to load My Assigned Reports</h2>
        <p>{e}</p>
        <a href="/maintenance-dashboard">Back to Dashboard</a>
        """, 500
    
# =========================
# MAINTENANCE DONE ASSIGNED
# =========================

@app.route("/maintenance-done")
def maintenance_done():

    if "user_id" not in session:
        return redirect("/")

    if session.get("role") != "maintenance":
        if session.get("role") == "admin":
            return redirect("/admin-dashboard")
        return redirect("/dashboard")

    try:
        result = (
            supabase.table("facility_reports")
            .select("*")
            .eq("assigned_to", session["user_id"])
            .eq("status", "RESOLVED")
            .order("created_at", desc=True)
            .execute()
        )

        reports = result.data or []

        return render_template(
            "maintenance-done.html",
            fullname=session.get("fullname", "Maintenance"),
            reports=reports
        )

    except Exception as e:
        app.logger.exception("Failed to load completed reports")
        return f"""
        <h2>Unable to load Done Assigned</h2>
        <p>{e}</p>
        <a href="/maintenance-dashboard">Back to Dashboard</a>
        """, 500


def send_reset_email(to_email, reset_url):
    service_id = os.getenv("EMAILJS_SERVICE_ID")
    template_id = os.getenv("EMAILJS_TEMPLATE_ID")
    public_key = os.getenv("EMAILJS_PUBLIC_KEY")
    private_key = os.getenv("EMAILJS_PRIVATE_KEY")

    # Check EmailJS settings
    if not all([
        service_id,
        template_id,
        public_key,
        private_key
    ]):
        raise RuntimeError(
            "EmailJS configuration is incomplete. "
            "Check the Render environment variables."
        )

    # Send email through EmailJS
    try:
        response = requests.post(
            "https://api.emailjs.com/api/v1.0/email/send",
            json={
                "service_id": service_id,
                "template_id": template_id,
                "user_id": public_key,
                "accessToken": private_key,
                "template_params": {
                    "to_email": to_email,
                    "reset_url": reset_url
                }
            },
            timeout=20
        )

        if response.status_code != 200:
            app.logger.error(
                "EmailJS error: status=%s body=%s",
                response.status_code,
                response.text[:300]
            )
            raise RuntimeError(
                "EmailJS could not send the email."
            )

        app.logger.info(
            "Password reset email accepted by EmailJS."
        )

    except requests.RequestException:
        app.logger.exception(
            "EmailJS network request failed."
        )
        raise RuntimeError(
            "Unable to connect to the email service."
        )
# =========================
# LOGOUT
# =========================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")


# =========================
# RUN FLASK
# =========================

if __name__ == "__main__":
    app.run(debug=True)
