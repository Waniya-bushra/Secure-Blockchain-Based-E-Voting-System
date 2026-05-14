from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import hashlib
import json

db = SQLAlchemy()


# ─────────────────────────────────────────────
# Eligible voters — admin whitelist by email
# ─────────────────────────────────────────────
class EligibleVoter(db.Model):
    __tablename__ = 'eligible_voters'
    id    = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name  = db.Column(db.String(100), nullable=False)


# ─────────────────────────────────────────────
# Candidates — per position (4 positions, 2 each)
# A candidate can only contest ONE position
# ─────────────────────────────────────────────
class Candidate(db.Model):
    __tablename__ = 'candidates'
    id       = db.Column(db.Integer, primary_key=True)
    name     = db.Column(db.String(100), unique=True, nullable=False)  # globally unique
    position = db.Column(db.String(50),  nullable=False)               # president, vp, secretary, treasurer


# ─────────────────────────────────────────────
# Registered students (email-based)
# ─────────────────────────────────────────────
class Student(db.Model):
    __tablename__ = 'students'
    id            = db.Column(db.Integer, primary_key=True)
    email         = db.Column(db.String(100), unique=True, nullable=False)
    name          = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_verified   = db.Column(db.Boolean, default=False)

    login_attempts = db.Column(db.Integer,  default=0)
    locked_until   = db.Column(db.DateTime, nullable=True)

    otp_code    = db.Column(db.String(6),  nullable=True)
    otp_expires = db.Column(db.DateTime,   nullable=True)

    # One-time voting window
    voting_started_at = db.Column(db.DateTime, nullable=True)
    voting_closed_at  = db.Column(db.DateTime, nullable=True)
    has_voted_ever    = db.Column(db.Boolean,  default=False)


# ─────────────────────────────────────────────
# Which student voted for which position
# One vote per position per student
# ─────────────────────────────────────────────
class VotedRecord(db.Model):
    __tablename__ = 'voted_records'
    id         = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=False)
    position   = db.Column(db.String(50), nullable=False)
    __table_args__ = (db.UniqueConstraint('student_id', 'position'),)


# ─────────────────────────────────────────────
# Anonymous vote record
# ─────────────────────────────────────────────
class Vote(db.Model):
    __tablename__ = 'votes'
    id             = db.Column(db.Integer, primary_key=True)
    position       = db.Column(db.String(50),  nullable=False)
    candidate_name = db.Column(db.String(100), nullable=False)
    vote_token     = db.Column(db.String(200), unique=True)
    vote_hash      = db.Column(db.String(200))
    block_hash     = db.Column(db.String(200))
    prev_hash      = db.Column(db.String(200))
    timestamp      = db.Column(db.DateTime, default=datetime.utcnow)


# ─────────────────────────────────────────────
# Tamper-evident audit log (HMAC-chained)
# ─────────────────────────────────────────────
class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id        = db.Column(db.Integer, primary_key=True)
    username  = db.Column(db.String(100))
    action    = db.Column(db.String(200))
    ip_addr   = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    log_hash  = db.Column(db.String(200))


# ─────────────────────────────────────────────
# Blockchain vote ledger
# ─────────────────────────────────────────────
class BlockchainVote(db.Model):
    __tablename__ = 'blockchain_votes'
    id         = db.Column(db.Integer, primary_key=True)
    index      = db.Column(db.Integer,     nullable=False)
    position   = db.Column(db.String(50),  nullable=False)
    candidate  = db.Column(db.String(100), nullable=False)
    vote_token = db.Column(db.String(200), nullable=False)
    timestamp  = db.Column(db.String(50),  nullable=False)
    prev_hash  = db.Column(db.String(200), nullable=False)
    block_hash = db.Column(db.String(200), nullable=False)

    def compute_hash(self):
        block_string = json.dumps({
            'index':     self.index,
            'position':  self.position,
            'candidate': self.candidate,
            'vote_token':self.vote_token,
            'timestamp': self.timestamp,
            'prev_hash': self.prev_hash
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()


# ─────────────────────────────────────────────
# RSA-signed final election results
# ─────────────────────────────────────────────
class ElectionResult(db.Model):
    __tablename__ = 'election_results'
    id           = db.Column(db.Integer, primary_key=True)
    results_json = db.Column(db.Text,    nullable=False)
    signature    = db.Column(db.Text,    nullable=False)
    signed_at    = db.Column(db.DateTime, default=datetime.utcnow)
    signed_by    = db.Column(db.String(50), default='admin')