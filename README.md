# 🛡️ Login Security Monitoring System

A simple, beginner-friendly **College-Level Cybersecurity Web Application** built with **Python Flask** and **MySQL (XAMPP)** to demonstrate secure user authentication, login anomaly monitoring (successful vs. failed attempts), and CRUD operations for cybersecurity incident events.

---

## 📌 Features

1. **Authentication & Security**
   - User Registration & Login with form validation.
   - Secure password hashing using `werkzeug.security` (`generate_password_hash` / `check_password_hash`).
   - Session-based access control with login protection on all dashboard routes.
   - Parameterized SQL queries to prevent SQL Injection.

2. **Login Security Monitoring**
   - Real-time logging of all authentication attempts into MySQL table `login_logs`.
   - Records username, status (`SUCCESS` / `FAILED`), client IP address, and exact timestamp.

3. **Admin Dashboard**
   - Dynamic summary cards:
     - 👥 Total Registered Users
     - 🟢 Total Successful Logins
     - 🔴 Total Failed Logins
     - ⚠️ Total Security Events
   - Recent login activities table with color-coded status badges.

4. **Cybersecurity Events CRUD**
   - **Create**: Add new security threat events with severity levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
   - **Read**: View structured table of all security events and login logs.
   - **Update**: Edit existing security events and change classifications.
   - **Delete**: Remove resolved security events or unwanted login log records.

---

## 📁 Project Structure

```text
Login-Security-Monitoring-System/
│
├── app.py                  # Main Flask application with routes and MySQL queries
├── database.sql            # MySQL schema & sample data for XAMPP phpMyAdmin
├── requirements.txt        # Python package dependencies
├── README.md               # Setup and testing documentation
│
├── static/
│   └── style.css           # Custom clean styling & badges
│
└── templates/
    ├── login.html           # User login page
    ├── register.html        # User registration page
    ├── dashboard.html       # Analytics dashboard & summary cards
    ├── login_logs.html      # Authentication logs monitoring table
    ├── security_events.html # Security incident logs management table
    ├── add_event.html       # Form to add a new security event
    └── edit_event.html      # Form to update an existing security event
```

---

## 🛠️ Step-by-Step Setup Guide

### Step 1: Start XAMPP
1. Open the **XAMPP Control Panel**.
2. Click **Start** next to **Apache**.
3. Click **Start** next to **MySQL**.
*(Ensure the port for MySQL is `3306`, which is default).*

---

### Step 2: Import the Database in phpMyAdmin
1. Open your browser and navigate to: [http://localhost/phpmyadmin](http://localhost/phpmyadmin)
2. Click on the **Import** tab at the top.
3. Click **Choose File** and select `database.sql` from this project directory (`Login-Security-Monitoring-System/database.sql`).
4. Scroll to the bottom and click **Import** (or **Go**).
5. The database `login_security_db` and tables (`users`, `login_logs`, `security_events`) will be created automatically.

---

### Step 3: Install Python Dependencies
Open your terminal (PowerShell, Command Prompt, or VS Code Terminal) in the project directory:

```bash
pip install -r requirements.txt
```

---

### Step 4: Run the Flask Application
Start the Flask development server by running:

```bash
python app.py
```

You will see the startup confirmation:
```text
============================================================
 Login Security Monitoring System is starting...
 Running locally at: http://127.0.0.1:5000
============================================================
```

---

### Step 5: Access the Web Application
Open your browser and visit:
👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## 🧪 Demonstration & Testing Checklist

To demonstrate all features during a college presentation:

1. **Test Registration**:
   - Go to [http://127.0.0.1:5000/register](http://127.0.0.1:5000/register).
   - Create a user (e.g., username: `admin`, password: `password123`).
   - Check phpMyAdmin `users` table to demonstrate that the password is encrypted/hashed.

2. **Test Failed Login Monitoring**:
   - Go to [http://127.0.0.1:5000/login](http://127.0.0.1:5000/login).
   - Enter `admin` with a wrong password like `wrongpass`.
   - Notice the red alert: *"Invalid username or password. This attempt has been logged."*

3. **Test Successful Login**:
   - Enter `admin` and `password123`.
   - You are redirected to the Dashboard.

4. **Verify Dashboard & Login Logs**:
   - The dashboard updates counters: **Total Users**, **Successful Logins**, and **Failed Logins**.
   - Click **Login Logs** to view the full audit trail showing the failed attempt in red and the successful attempt in green.

5. **Test Security Events CRUD**:
   - Go to **Security Events**.
   - Click **Add Security Event** and submit an incident (e.g., *"DDoS Simulation on port 80"*, Severity: `HIGH`).
   - Click **Edit** on any record to update its description or severity.
   - Click **Delete** to delete a record.

6. **Test Logout**:
   - Click **Logout**. The session is terminated and protected pages cannot be accessed directly without logging in again.

---

## 🛡️ Database Schema Overview

| Table | Columns | Purpose |
| :--- | :--- | :--- |
| `users` | `id`, `username`, `password`, `created_at` | Stores user credentials with hashed passwords |
| `login_logs` | `id`, `username`, `status`, `ip_address`, `login_time` | Stores all login attempts (`SUCCESS` / `FAILED`) |
| `security_events` | `id`, `event_type`, `description`, `severity`, `created_at` | Stores cybersecurity incident data for CRUD |
