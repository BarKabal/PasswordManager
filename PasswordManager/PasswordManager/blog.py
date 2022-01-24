from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
from werkzeug.exceptions import abort

from PasswordManager.auth import login_required
from PasswordManager.db import get_db
import PasswordManager.encryption as encrypt

bp = Blueprint('blog', __name__)

@bp.route('/')
@login_required
def index():
    db = get_db()
    records = db.execute(
        'SELECT r.id, site_url, used_login, used_email, author_id'
        ' FROM record r JOIN user u ON r.author_id = u.id'
        ' WHERE r.author_id = ?',
        (g.user['id'],)
    ).fetchall()
    return render_template('blog/index.html', records=records)


@bp.route('/check_master_password', methods=['POST'])
@login_required
def check_master_password():
    db = get_db()
    master_pass = request.form['master_password']
    user_data = db.execute(
        'SELECT username, username_encrypted'
        ' FROM user u'
        ' WHERE u.id = ?',
        (g.user['id'],)
    ).fetchall()
    records = None
    passwords = []
    if encrypt.check_master(master_pass, user_data[0][0], user_data[0][1]):
        records = db.execute(
            'SELECT r.id, site_url, used_login, used_email, used_password, author_id'
            ' FROM record r JOIN user u ON r.author_id = u.id'
            ' WHERE r.author_id = ?',
            (g.user['id'],)
        ).fetchall()

        for record in records:
            passwords.append(encrypt.AES_decrypt(record[4], master_pass))
    else:
        records = db.execute(
            'SELECT r.id, site_url, used_login, used_email, author_id'
            ' FROM record r JOIN user u ON r.author_id = u.id'
            ' WHERE r.author_id = ?',
        (g.user['id'],)
    ).fetchall()
    return render_template('blog/index.html', records=records, passwords=passwords, number=len(passwords))

#O$qvd386Q0FSZoK!

@bp.route('/create', methods=('GET', 'POST'))
@login_required
def create():
    if request.method == 'POST':
        db = get_db()
        given_master_password = request.form['master_password']
        site_url = request.form['site_url']
        used_login = request.form['used_login']
        used_email = request.form['used_email']
        used_password = request.form['used_password']
        error = None
        user_data = db.execute(
            'SELECT username, username_encrypted'
            ' FROM user u'
            ' WHERE u.id = ?',
            (g.user['id'],)
        ).fetchall()

        if not site_url:
            error = 'URL is required.'
        if not used_password:
            error = 'Password is required'
        if not given_master_password:
            error = 'Master password is required'
        if not encrypt.check_master(given_master_password, user_data[0][0], user_data[0][1]):
            error = 'Wrong master password'

        if error is not None:
            flash(error)
        else:
            used_password_encrypted = encrypt.AES_encrypt(used_password, given_master_password)
            db.execute(
                'INSERT INTO record (site_url, used_login, used_email, used_password, author_id)'
                ' VALUES (?, ?, ?, ?, ?)',
                (site_url, used_login, used_email, used_password_encrypted, g.user['id'])
            )
            db.commit()
            return redirect(url_for('blog.index'))

    return render_template('blog/create.html')

def get_record(id, check_author=True):
    record = get_db().execute(
        'SELECT r.id, site_url, used_login, used_email, used_password, author_id'
        ' FROM record r JOIN user u ON r.author_id = u.id'
        ' WHERE r.id = ?',
        (id,)
    ).fetchone()

    if record is None:
        abort(404, f"Record id {id} doesn't exist.")

    if check_author and record['author_id'] != g.user['id']:
        abort(403)

    return record

@bp.route('/<int:id>/delete', methods=('POST',))
@login_required
def delete(id):
    get_record(id)
    db = get_db()
    db.execute('DELETE FROM record WHERE id = ?', (id,))
    db.commit()
    return redirect(url_for('blog.index'))