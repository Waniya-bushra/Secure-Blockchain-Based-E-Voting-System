import bcrypt
import smtplib
from email.mime.text import MIMEText
from email.utils import formataddr
from flask import request
from datetime import datetime, timedelta
from models import db, Student, EligibleVoter, AuditLog
from crypto import compute_log_hmac, generate_otp
from config import Config


def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())


def check_password_strength(password):
    errors = []
    if len(password) < 8:
        errors.append('At least 8 characters required')
    if not any(c.isupper() for c in password):
        errors.append('At least one uppercase letter required')
    if not any(c.isdigit() for c in password):
        errors.append('At least one number required')
    if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        errors.append('At least one special character required')
    return errors


def log_action(username, action):
    last      = AuditLog.query.order_by(AuditLog.id.desc()).first()
    prev_hash = last.log_hash if last else '0' * 64
    entry     = {'user': username, 'action': action,
                 'ip': request.remote_addr, 'time': str(datetime.utcnow())}
    new_hash  = compute_log_hmac(entry, prev_hash)
    db.session.add(AuditLog(
        username=username, action=action,
        ip_addr=request.remote_addr, log_hash=new_hash
    ))
    db.session.commit()


def check_account_locked(student):
    return bool(student.locked_until and datetime.utcnow() < student.locked_until)


def handle_failed_login(student):
    student.login_attempts += 1
    if student.login_attempts >= Config.MAX_LOGIN_ATTEMPTS:
        student.locked_until   = datetime.utcnow() + timedelta(minutes=Config.LOCKOUT_MINUTES)
        student.login_attempts = 0
    db.session.commit()


def _send_email_otp(to_email, to_name, otp, subject_tag='OTP Code'):
    try:
        body = (f"Hello {to_name},\n\n"
                f"Your IEEE IOBM e-Voting {subject_tag} is: {otp}\n\n"
                f"This code expires in 10 minutes. Do NOT share it.\n\n"
                f"— IEEE IOBM e-Voting System")
        msg            = MIMEText(body)
        msg['Subject'] = f'IEEE IOBM e-Voting: {subject_tag}'
        msg['From']    = formataddr(('IEEE IOBM Student Branch', Config.MAIL_USERNAME))
        msg['To']      = to_email
        with smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT) as smtp:
            smtp.starttls()
            smtp.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
            smtp.send_message(msg)
        return True, ''
    except Exception as e:
        return False, str(e)
def register_student(email, password):
    email = email.lower().strip()

    eligible = EligibleVoter.query.filter_by(email=email).first()
    if not eligible:
        return None, 'This email is not on the approved voter list. Contact admin.'

    existing = Student.query.filter_by(email=email).first()
    if existing:
        if existing.is_verified:
            return None, 'An account with this email already exists.'
        # Resend OTP for unverified account
        otp = generate_otp()
        existing.otp_code    = otp
        existing.otp_expires = datetime.utcnow() + timedelta(minutes=10)
        db.session.commit()
        _send_email_otp(email, existing.name, otp, 'Verification Code')
        return existing, None

    errors = check_password_strength(password)
    if errors:
        return None, ' | '.join(errors)

    otp     = generate_otp()
    student = Student(
        email=email, name=eligible.name,
        password_hash=hash_password(password),
        is_verified=False, otp_code=otp,
        otp_expires=datetime.utcnow() + timedelta(minutes=10)
    )
    db.session.add(student)
    db.session.commit()

    ok, err = _send_email_otp(email, eligible.name, otp, 'Verification Code')
    if not ok:
        db.session.delete(student)
        db.session.commit()
        return None, f'Failed to send verification email: {err}'

    return student, None


def verify_otp(student, otp_entered):
    if not student.otp_code or not student.otp_expires:
        return False, 'No OTP found. Please try again.'
    if datetime.utcnow() > student.otp_expires:
        student.otp_code = None
        student.otp_expires = None
        db.session.commit()
        return False, 'OTP has expired. Please try again.'
    if student.otp_code != otp_entered.strip():
        return False, 'Incorrect OTP. Please try again.'
    student.otp_code    = None
    student.otp_expires = None
    if not student.is_verified:
        student.is_verified = True
    db.session.commit()
    return True, ''


def verify_student(email, password):
    email   = email.lower().strip()
    student = Student.query.filter_by(email=email).first()
    if not student:
        return None, 'Email not found. Please register first.'
    if not student.is_verified:
        return None, 'Account not verified. Check your email for the OTP.'
    if check_account_locked(student):
        remaining = (student.locked_until - datetime.utcnow()).seconds // 60
        return None, f'Account locked. Try again in {remaining} minutes.'
    # Note: voting_closed_at does NOT block login anymore.
    # After election finalization, users can still log in to view results.
    # Vote blocking is handled at the /vote route level.
    if not check_password(password, student.password_hash):
        handle_failed_login(student)
        left = Config.MAX_LOGIN_ATTEMPTS - student.login_attempts
        return None, f'Wrong password. {left} attempts remaining.'
    student.login_attempts = 0
    student.locked_until   = None
    db.session.commit()
    return student, None


def send_otp(student):
    otp = generate_otp()
    student.otp_code    = otp
    student.otp_expires = datetime.utcnow() + timedelta(minutes=10)
    db.session.commit()
    return _send_email_otp(student.email, student.name, otp, 'Login OTP')


def start_voting_session(student):
    if not student.voting_started_at:
        student.voting_started_at = datetime.utcnow()
        db.session.commit()
    return student.voting_started_at + timedelta(minutes=Config.VOTING_MINUTES)


def close_voting_session(student, reason='timer_expired'):
    if not student.voting_closed_at:
        student.voting_closed_at = datetime.utcnow()
        db.session.commit()
        log_action(student.email, f'VOTING SESSION CLOSED — {reason}')


def is_voting_window_open(student):
    if student.voting_closed_at:
        return False, None
    if not student.voting_started_at:
        return True, None
    deadline = student.voting_started_at + timedelta(minutes=Config.VOTING_MINUTES)
    if datetime.utcnow() > deadline:
        close_voting_session(student, reason='timer_expired')
        return False, None
    return True, deadline