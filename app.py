from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from datetime import datetime, timedelta
import json

from config import Config
from models import (db, Student, EligibleVoter, Candidate, Vote,
                    VotedRecord, AuditLog, BlockchainVote, ElectionResult)
from auth import (log_action, verify_student, send_otp, verify_otp,
                  register_student, start_voting_session,
                  close_voting_session, is_voting_window_open)
from crypto import (generate_vote_token, hash_vote, compute_block_hash,
                    verify_blockchain, sign_results, verify_results,
                    get_public_key_pem)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']        = 'sqlite:///database.db'
app.config['SECRET_KEY']                     = Config.SECRET_KEY
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

POSITIONS = [
    {'id': 'president',  'title': 'President',        'icon': '👑'},
    {'id': 'vp',         'title': 'Vice President',    'icon': '🌟'},
    {'id': 'secretary',  'title': 'General Secretary', 'icon': '📋'},
    {'id': 'treasurer',  'title': 'Treasurer',         'icon': '💰'},
]
POSITION_IDS = [p['id'] for p in POSITIONS]


def get_positions_with_candidates():
    result = []
    for p in POSITIONS:
        cands = Candidate.query.filter_by(position=p['id']).all()
        result.append({
            'id':         p['id'],
            'title':      p['title'],
            'icon':       p['icon'],
            'candidates': [{'id': c.id, 'name': c.name, 'position': c.position} for c in cands]
        })
    return result


def seed_data():
    if EligibleVoter.query.count() == 0:
        voters = [
            ('std_34552@iobm.edu.pk', 'Zoya Nayab'),
            ('std_35176@iobm.edu.pk', 'Waniya Bushra'),
            ('std_34573@iobm.edu.pk', 'Ammara Khan'),
            ('std_34507@iobm.edu.pk', 'Ayaan Nadeem'),
            ('std_33872@iobm.edu.pk', 'Moiz Ali Siddiqui'),
            ('std_33961@iobm.edu.pk', 'Rafay Sheikh'),
            ('std_34858@iobm.edu.pk', 'Muhammad Abdullah'),
            ('std_33842@iobm.edu.pk', 'Abdul Wasay'),
            ('std_34797@iobm.edu.pk', 'Reejah Fatima'),
            ('std_33729@iobm.edu.pk', 'Kinza Ali'),
            ('std_38001@iobm.edu.pk', 'Hamna Saleem'),
            ('std_38002@iobm.edu.pk', 'Adeen Gul'),
            ('std_38003@iobm.edu.pk', 'Muhammad Anus'),
            ('std_38005@iobm.edu.pk', 'Abeeha Asif'),
            ('std_38006@iobm.edu.pk', 'Ashir Ali'),
            ('std_38007@iobm.edu.pk', 'Syed Haad'),
        ]
        for email, name in voters:
            db.session.add(EligibleVoter(email=email, name=name))
        db.session.commit()

    if Candidate.query.count() == 0:
        candidates = [
            ('Hamna Saleem',  'president'),
            ('Adeen Gul',     'president'),
            ('Muhammad Anus', 'vp'),
            ('Zoya Nayab',    'vp'),
            ('Moiz Ali',      'secretary'),
            ('Abeeha Asif',   'secretary'),
            ('Ashir Ali',     'treasurer'),
            ('Syed Haad',     'treasurer'),
        ]
        for name, pos in candidates:
            db.session.add(Candidate(name=name, position=pos))
        db.session.commit()


def get_current_student():
    sid = session.get('student_id')
    return Student.query.get(sid) if sid else None


def is_election_finalized():
    """Returns True if admin has signed and finalized the election."""
    return ElectionResult.query.count() > 0


# ═══════════════════════════════
# STUDENT ROUTES
# ═══════════════════════════════

@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('student_id'):
        return redirect(url_for('vote'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        pw    = request.form.get('password', '')
        student, error = verify_student(email, pw)
        if error:
            log_action(email, f'FAILED LOGIN: {error}')
            return render_template('login.html', error=error)
        send_otp(student)
        session['pending_otp_id'] = student.id
        log_action(email, 'LOGIN OTP SENT')
        return redirect(url_for('verify_otp_route'))
    return render_template('login.html')


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp_route():
    pending_id = session.get('pending_otp_id')
    if not pending_id:
        return redirect(url_for('login'))
    if request.method == 'POST':
        student = Student.query.get(pending_id)
        if not student:
            return redirect(url_for('login'))
        ok, error = verify_otp(student, request.form.get('otp', ''))
        if not ok:
            log_action(student.email, f'OTP FAILED: {error}')
            return render_template('otp_verify.html', error=error)
        session.pop('pending_otp_id', None)
        session['student_id']    = student.id
        session['student_name']  = student.name
        session['student_email'] = student.email
        log_action(student.email, 'LOGIN SUCCESS (2FA passed)')
        # If election finalized, go to results instead of vote
        if is_election_finalized():
            return redirect(url_for('student_results'))
        return redirect(url_for('vote'))
    return render_template('otp_verify.html')


# ── Resend OTP for login 2FA ──
@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    pending_id = session.get('pending_otp_id') or session.get('reg_pending_id')
    if not pending_id:
        return jsonify({'error': 'No pending session. Please log in again.'}), 400
    student = Student.query.get(pending_id)
    if not student:
        return jsonify({'error': 'Student not found.'}), 404
    ok, err = send_otp(student)
    if not ok:
        return jsonify({'error': f'Failed to send OTP: {err}'}), 500
    log_action(student.email, 'OTP RESENT')
    return jsonify({'success': True, 'message': 'A new OTP has been sent to your email.'})


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email   = request.form.get('email', '').strip()
        pw      = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        if pw != confirm:
            return render_template('register.html', error='Passwords do not match.')
        student, error = register_student(email, pw)
        if error:
            log_action(email, f'REGISTRATION FAILED: {error}')
            return render_template('register.html', error=error)
        session['reg_pending_id'] = student.id
        log_action(email, 'REGISTRATION OTP SENT')
        return redirect(url_for('verify_registration_otp'))
    return render_template('register.html')


@app.route('/verify-registration', methods=['GET', 'POST'])
def verify_registration_otp():
    pending_id = session.get('reg_pending_id')
    if not pending_id:
        return redirect(url_for('register'))
    if request.method == 'POST':
        student = Student.query.get(pending_id)
        if not student:
            return redirect(url_for('register'))
        ok, error = verify_otp(student, request.form.get('otp', ''))
        if not ok:
            log_action(student.email, f'REG OTP FAILED: {error}')
            return render_template('otp_verify.html', error=error, context='registration')
        session.pop('reg_pending_id', None)
        log_action(student.email, 'ACCOUNT ACTIVATED')
        return render_template('register.html',
                               success='Account verified! You can now log in.')
    return render_template('otp_verify.html', context='registration')


@app.route('/vote', methods=['GET', 'POST'])
def vote():
    student = get_current_student()
    if not student:
        return redirect(url_for('login'))

    # Check if election has been finalized by admin
    if is_election_finalized():
        return redirect(url_for('student_results'))

    window_open, deadline = is_voting_window_open(student)
    if not window_open:
        log_action(student.email, 'VOTING ACCESS DENIED — window closed')
        return redirect(url_for('student_results'))

    if request.method == 'POST':
        position  = request.form.get('position', '').strip()
        candidate = request.form.get('candidate', '').strip()

        if is_election_finalized():
            return jsonify({'error': 'Election has been finalized. Voting is closed.'}), 403

        window_open, deadline = is_voting_window_open(student)
        if not window_open:
            return jsonify({'error': 'Your voting time has expired.'}), 403

        if position not in POSITION_IDS:
            return jsonify({'error': 'Invalid position.'}), 400

        cand_obj = Candidate.query.filter_by(name=candidate, position=position).first()
        if not cand_obj:
            return jsonify({'error': 'Invalid candidate for this position.'}), 400

        already = VotedRecord.query.filter_by(student_id=student.id, position=position).first()
        if already:
            return jsonify({'error': 'You have already voted for this position.'}), 400

        token = generate_vote_token(student.id, position)
        vhash = hash_vote(candidate, position, token)
        db.session.add(Vote(position=position, candidate_name=candidate,
                            vote_token=token, vote_hash=vhash))
        db.session.add(VotedRecord(student_id=student.id, position=position))

        last      = BlockchainVote.query.order_by(BlockchainVote.index.desc()).first()
        prev_hash = last.block_hash if last else '0' * 64
        idx       = (last.index + 1) if last else 0
        ts        = datetime.utcnow().isoformat()
        bhash     = compute_block_hash(idx, position, candidate, token, ts, prev_hash)
        db.session.add(BlockchainVote(index=idx, position=position, candidate=candidate,
                                      vote_token=token, timestamp=ts,
                                      prev_hash=prev_hash, block_hash=bhash))
        student.has_voted_ever = True
        db.session.commit()
        log_action(student.email, f'VOTED for {position} (anonymized)')

        voted_count = VotedRecord.query.filter_by(student_id=student.id).count()
        if voted_count >= len(POSITIONS):
            close_voting_session(student, reason='all_positions_voted')
            session.clear()
            return jsonify({'success': True, 'all_done': True})
        return jsonify({'success': True, 'all_done': False})

    deadline  = start_voting_session(student)
    voted_set = {r.position for r in VotedRecord.query.filter_by(student_id=student.id).all()}
    positions = get_positions_with_candidates()
    # Pass candidate names only for vote.html
    positions_simple = []
    for p in positions:
        positions_simple.append({
            'id': p['id'], 'title': p['title'], 'icon': p['icon'],
            'candidates': [c['name'] for c in p['candidates']]
        })
    return render_template('vote.html', positions=positions_simple,
                           voted=voted_set, name=student.name,
                           deadline=deadline.isoformat())


@app.route('/vote-closed')
def vote_closed():
    return render_template('vote_closed.html')


@app.route('/logout')
def logout():
    student = get_current_student()
    if student:
        close_voting_session(student, reason='logged_out')
        log_action(student.email, 'LOGOUT')
    session.clear()
    return redirect(url_for('login'))


# ═══════════════════════════════
# ADMIN ROUTES
# ═══════════════════════════════

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        if (request.form.get('username') == Config.ADMIN_USERNAME and
                request.form.get('password') == Config.ADMIN_PASSWORD):
            session['admin'] = True
            log_action('ADMIN', 'ADMIN LOGIN SUCCESS')
            return redirect(url_for('admin'))
        log_action('ADMIN', 'FAILED ADMIN LOGIN')
        return render_template('admin.html', login=True, error='Wrong credentials')

    if not session.get('admin'):
        return render_template('admin.html', login=True)

    positions = get_positions_with_candidates()
    results   = {}
    for p in positions:
        results[p['id']] = {'title': p['title'], 'icon': p['icon'], 'candidates': {}}
        for cand in p['candidates']:
            results[p['id']]['candidates'][cand['name']] = {
                'count': Vote.query.filter_by(position=p['id'], candidate_name=cand['name']).count(),
                'id':    cand['id']
            }

    logs          = AuditLog.query.order_by(AuditLog.id.desc()).limit(50).all()
    total         = Vote.query.count()
    signed_result = ElectionResult.query.order_by(ElectionResult.id.desc()).first()
    blocks        = BlockchainVote.query.order_by(BlockchainVote.index).all()
    chain_ok, chain_msg = verify_blockchain(blocks) if blocks else (True, 'No votes yet')

    return render_template('admin.html', login=False,
                           results=results, logs=logs, total=total,
                           signed_result=signed_result,
                           chain_ok=chain_ok, chain_msg=chain_msg,
                           total_eligible=EligibleVoter.query.count(),
                           total_registered=Student.query.filter_by(is_verified=True).count(),
                           total_voted=Student.query.filter(Student.has_voted_ever == True).count(),
                           positions=positions)


# ── Voters list page ──
@app.route('/admin/voters')
def admin_voters():
    if not session.get('admin'):
        return redirect(url_for('admin'))
    search = request.args.get('q', '').strip()
    query  = EligibleVoter.query
    if search:
        like = f'%{search}%'
        query = query.filter(
            db.or_(
                EligibleVoter.name.ilike(like),
                EligibleVoter.email.ilike(like)
            )
        )
    page    = request.args.get('page', 1, type=int)
    per_page = 10
    voters  = query.order_by(EligibleVoter.name).paginate(page=page, per_page=per_page, error_out=False)
    return render_template('admin_voters.html', voters=voters, search=search)


# ── Add voter ──
@app.route('/admin/add-voter', methods=['POST'])
def admin_add_voter():
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    email = request.form.get('email', '').strip().lower()
    name  = request.form.get('name', '').strip()
    if not email or not name:
        return jsonify({'error': 'Email and name required'}), 400
    if EligibleVoter.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already on voter list'}), 400
    db.session.add(EligibleVoter(email=email, name=name))
    db.session.commit()
    log_action('ADMIN', f'ADDED VOTER: {email}')
    return jsonify({'success': True})


# ── Delete voter ──
@app.route('/admin/delete-voter/<int:voter_id>', methods=['POST'])
def admin_delete_voter(voter_id):
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    voter = EligibleVoter.query.get(voter_id)
    if not voter:
        return jsonify({'error': 'Voter not found'}), 404
    log_action('ADMIN', f'DELETED VOTER: {voter.email}')
    db.session.delete(voter)
    db.session.commit()
    return jsonify({'success': True})


# ── Add candidate ──
@app.route('/admin/add-candidate', methods=['POST'])
def admin_add_candidate():
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    name     = request.form.get('name', '').strip()
    position = request.form.get('position', '').strip()
    if not name or not position:
        return jsonify({'error': 'Name and position required'}), 400
    existing = Candidate.query.filter_by(name=name).first()
    if existing:
        return jsonify({'error': f'"{name}" is already contesting for {existing.position}. '
                                 f'A candidate cannot stand for two positions.'}), 400
    if position not in POSITION_IDS:
        return jsonify({'error': 'Invalid position'}), 400
    db.session.add(Candidate(name=name, position=position))
    db.session.commit()
    log_action('ADMIN', f'ADDED CANDIDATE: {name} → {position}')
    return jsonify({'success': True})


# ── Delete candidate ──
@app.route('/admin/delete-candidate/<int:cand_id>', methods=['POST'])
def admin_delete_candidate(cand_id):
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    cand = Candidate.query.get(cand_id)
    if not cand:
        return jsonify({'error': 'Candidate not found'}), 404
    log_action('ADMIN', f'DELETED CANDIDATE: {cand.name}')
    db.session.delete(cand)
    db.session.commit()
    return jsonify({'success': True})


# ── Sign results ──
@app.route('/admin/sign-results', methods=['POST'])
def sign_election_results():
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    positions = get_positions_with_candidates()
    results   = {}
    for p in positions:
        results[p['id']] = {'title': p['title'], 'candidates': {}}
        for cand in p['candidates']:
            results[p['id']]['candidates'][cand['name']] = Vote.query.filter_by(
                position=p['id'], candidate_name=cand['name']).count()
    rj  = json.dumps(results, sort_keys=True)
    sig = sign_results(rj)
    db.session.add(ElectionResult(results_json=rj, signature=sig))
    db.session.commit()
    # Close all still-open voting sessions
    open_students = Student.query.filter(
        Student.is_verified == True,
        Student.voting_closed_at == None,
        Student.voting_started_at != None
    ).all()
    for s in open_students:
        s.voting_closed_at = datetime.utcnow()
    db.session.commit()

    log_action('ADMIN', f'RESULTS SIGNED WITH RSA — voting permanently closed for all users')
    return jsonify({'success': True, 'message': 'Results signed! Voting is now permanently closed.'})


# ── Student-facing results page (after finalization) ──
@app.route('/results')
def student_results():
    student = get_current_student()
    er = ElectionResult.query.order_by(ElectionResult.id.desc()).first()
    if not er:
        # Election not finalized yet
        if student:
            return redirect(url_for('vote'))
        return redirect(url_for('login'))

    results = json.loads(er.results_json)

    # Compute winners
    winners = {}
    for pos_id, pos_data in results.items():
        cands = pos_data.get('candidates', {})
        if cands:
            winner = max(cands, key=lambda k: cands[k] if isinstance(cands[k], int) else cands[k].get('count', 0) if isinstance(cands[k], dict) else 0)
            winners[pos_id] = {'name': winner, 'title': pos_data['title']}

    # Check if student voted
    voted_positions = set()
    if student:
        voted_positions = {r.position for r in VotedRecord.query.filter_by(student_id=student.id).all()}

    return render_template('student_results.html',
                           results=results,
                           winners=winners,
                           signed_at=er.signed_at,
                           student=student,
                           voted_positions=voted_positions,
                           positions=POSITIONS)


@app.route('/verify-results')
def verify_election_results():
    er = ElectionResult.query.order_by(ElectionResult.id.desc()).first()
    if not er:
        return render_template('verify_results.html', no_results=True)
    return render_template('verify_results.html',
                           is_valid=verify_results(er.results_json, er.signature),
                           signed_at=er.signed_at,
                           results=json.loads(er.results_json),
                           public_key=get_public_key_pem(),
                           signature=er.signature[:80] + '...')


with app.app_context():
    db.create_all()
    seed_data()
    from crypto import get_rsa_keys
    get_rsa_keys()

if __name__ == '__main__':
    app.run(debug=True)