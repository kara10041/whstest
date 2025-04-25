import sqlite3
import uuid
import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify
from flask_socketio import SocketIO, send, join_room, leave_room, emit
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
DATABASE = 'market.db'
socketio = SocketIO(app)

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 관리자 권한 체크 데코레이터
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        
        if not user or not user['is_admin']:
            flash('관리자 권한이 필요합니다.')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# 로그인 필요 데코레이터
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성 (관리자 구분, 계정 상태, 잔액 필드 추가)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                is_admin INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active',
                balance REAL DEFAULT 0.0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 상품 테이블 생성 (상태 필드 추가)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price REAL NOT NULL,
                seller_id TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 신고 테이블 생성 (상태 필드 추가)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 채팅방 테이블 추가
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_room (
                id TEXT PRIMARY KEY,
                product_id TEXT NOT NULL,
                buyer_id TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 채팅 메시지 테이블 추가
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_message (
                id TEXT PRIMARY KEY,
                room_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 거래 내역 테이블 추가 
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount REAL NOT NULL,
                product_id TEXT,
                status TEXT DEFAULT 'completed',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # 관리자 계정 생성 (기본 관리자: admin/admin)
        cursor.execute("SELECT * FROM user WHERE username = 'admin'")
        if cursor.fetchone() is None:
            admin_id = str(uuid.uuid4())
            cursor.execute("INSERT INTO user (id, username, password, is_admin) VALUES (?, ?, ?, ?)",
                        (admin_id, 'admin', 'admin', 1))
        
        db.commit()

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password, created_at) VALUES (?, ?, ?, ?)",
                       (user_id, username, password, datetime.datetime.now()))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        if user:
            # 계정 상태 확인
            if user['status'] == 'suspended':
                flash('이 계정은 정지되었습니다. 관리자에게 문의하세요.')
                return redirect(url_for('login'))
            
            session['user_id'] = user['id']
            session['is_admin'] = bool(user['is_admin'])
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('is_admin', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    
    # 검색 기능 추가
    search_query = request.args.get('search', '')
    if search_query:
        # 검색어가 있는 경우 해당 상품만 조회
        cursor.execute("""
            SELECT p.*, u.username as seller_name 
            FROM product p 
            JOIN user u ON p.seller_id = u.id
            WHERE p.status = 'active' AND (p.title LIKE ? OR p.description LIKE ?)
        """, (f'%{search_query}%', f'%{search_query}%'))
    else:
        # 모든 활성 상품 조회
        cursor.execute("""
            SELECT p.*, u.username as seller_name 
            FROM product p 
            JOIN user u ON p.seller_id = u.id
            WHERE p.status = 'active'
        """)
    
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user, search_query=search_query)

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        bio = request.form.get('bio', '')
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
    
    # 현재 사용자 정보
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    
    # 현재 사용자가 등록한 상품 조회
    cursor.execute("SELECT * FROM product WHERE seller_id = ? AND status = 'active'", (session['user_id'],))
    my_products = cursor.fetchall()
    
    # 거래 내역 조회
    cursor.execute("""
        SELECT t.*, 
               s.username as sender_name, 
               r.username as receiver_name,
               p.title as product_title
        FROM transactions t
        JOIN user s ON t.sender_id = s.id
        JOIN user r ON t.receiver_id = r.id
        LEFT JOIN product p ON t.product_id = p.id
        WHERE t.sender_id = ? OR t.receiver_id = ?
        ORDER BY t.created_at DESC
    """, (session['user_id'], session['user_id']))
    transactions = cursor.fetchall()
    
    return render_template('profile.html', user=current_user, products=my_products, transactions=transactions)

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
@login_required
def new_product():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = float(request.form['price'])  # 가격을 float으로 변환
        
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'], datetime.datetime.now())
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    if product['status'] != 'active' and (not session.get('is_admin') and session.get('user_id') != product['seller_id']):
        flash('해당 상품은 현재 이용할 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    
    is_owner = False
    if 'user_id' in session and session['user_id'] == product['seller_id']:
        is_owner = True
        
    return render_template('view_product.html', product=product, seller=seller, is_owner=is_owner)

# 상품 수정
@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ? AND seller_id = ?", (product_id, session['user_id']))
    product = cursor.fetchone()
    
    if not product and not session.get('is_admin'):
        flash('상품을 수정할 권한이 없습니다.')
        return redirect(url_for('dashboard'))
    
    if not product and session.get('is_admin'):
        cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
        product = cursor.fetchone()
        if not product:
            flash('상품을 찾을 수 없습니다.')
            return redirect(url_for('admin_products'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = float(request.form['price'])
        status = request.form.get('status', 'active')
        
        cursor.execute(
            "UPDATE product SET title = ?, description = ?, price = ?, status = ? WHERE id = ?",
            (title, description, price, status, product_id)
        )
        db.commit()
        flash('상품 정보가 업데이트되었습니다.')
        
        if session.get('is_admin'):
            return redirect(url_for('admin_products'))
        return redirect(url_for('view_product', product_id=product_id))
    
    return render_template('edit_product.html', product=product)

# 상품 삭제
@app.route('/product/<product_id>/delete', methods=['POST'])
@login_required
def delete_product(product_id):
    db = get_db()
    cursor = db.cursor()
    
    if session.get('is_admin'):
        cursor.execute("UPDATE product SET status = 'deleted' WHERE id = ?", (product_id,))
        db.commit()
        flash('상품이 삭제되었습니다.')
        return redirect(url_for('admin_products'))
    
    cursor.execute("SELECT * FROM product WHERE id = ? AND seller_id = ?", (product_id, session['user_id']))
    product = cursor.fetchone()
    
    if not product:
        flash('상품을 삭제할 권한이 없습니다.')
        return redirect(url_for('dashboard'))
    
    cursor.execute("UPDATE product SET status = 'deleted' WHERE id = ?", (product_id,))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('profile'))

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = request.form['reason']
        
        # 대상이 상품인지 유저인지 확인
        target_type = request.form.get('target_type', 'user')
        
        db = get_db()
        cursor = db.cursor()
        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason, created_at) VALUES (?, ?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason, datetime.datetime.now())
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    
    target_id = request.args.get('target_id')
    target_type = request.args.get('target_type', 'user')
    
    db = get_db()
    cursor = db.cursor()
    
    target_info = None
    if target_type == 'product':
        cursor.execute("SELECT * FROM product WHERE id = ?", (target_id,))
        target_info = cursor.fetchone()
    else:
        cursor.execute("SELECT * FROM user WHERE id = ?", (target_id,))
        target_info = cursor.fetchone()
    
    return render_template('report.html', target_id=target_id, target_type=target_type, target_info=target_info)

# 사용자 조회 기능
@app.route('/users')
@login_required
def users():
    if not session.get('is_admin'):
        return redirect(url_for('dashboard'))
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user ORDER BY created_at DESC")
    users = cursor.fetchall()
    return render_template('users.html', users=users)

# 송금 기능
@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    db = get_db()
    cursor = db.cursor()
    
    # 현재 사용자 정보
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    
    if request.method == 'POST':
        receiver_username = request.form['receiver']
        amount = float(request.form['amount'])
        product_id = request.form.get('product_id', None)
        
        # 금액 확인
        if amount <= 0:
            flash('송금 금액은 0보다 커야 합니다.')
            return redirect(url_for('transfer'))
        
        # 잔액 확인
        if current_user['balance'] < amount:
            flash('잔액이 부족합니다.')
            return redirect(url_for('transfer'))
        
        # 수신자 확인
        cursor.execute("SELECT * FROM user WHERE username = ?", (receiver_username,))
        receiver = cursor.fetchone()
        
        if not receiver:
            flash('해당 사용자를 찾을 수 없습니다.')
            return redirect(url_for('transfer'))
        
        if receiver['id'] == session['user_id']:
            flash('자신에게 송금할 수 없습니다.')
            return redirect(url_for('transfer'))
        
        # 송금 처리
        transaction_id = str(uuid.uuid4())
        
        # 송금자 잔액 감소
        cursor.execute("UPDATE user SET balance = balance - ? WHERE id = ?", (amount, session['user_id']))
        
        # 수신자 잔액 증가
        cursor.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (amount, receiver['id']))
        
        # 거래 내역 기록 - 수정 버전
        cursor.execute(
        'INSERT INTO transactions (id, sender_id, receiver_id, amount, product_id, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        (transaction_id, session['user_id'], receiver['id'], amount, product_id, datetime.datetime.now())
            )
        
        # 상품이 있는 경우 상품 상태 변경
        if product_id:
            cursor.execute("UPDATE product SET status = 'sold' WHERE id = ?", (product_id,))
        
        db.commit()
        flash(f'{amount}원이 {receiver_username}님에게 송금되었습니다.')
        return redirect(url_for('profile'))
    
    # 거래하려는 상품 ID가 있는 경우
    product_id = request.args.get('product_id')
    product = None
    seller = None
    
    if product_id:
        cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
        product = cursor.fetchone()
        
        if product and product['status'] == 'active':
            cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
            seller = cursor.fetchone()
    
    return render_template('transfer.html', user=current_user, product=product, seller=seller)

# 충전 기능 (잔액 충전)
@app.route('/deposit', methods=['GET', 'POST'])
@login_required
def deposit():
    if request.method == 'POST':
        amount = float(request.form['amount'])
        
        if amount <= 0:
            flash('충전 금액은 0보다 커야 합니다.')
            return redirect(url_for('deposit'))
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (amount, session['user_id']))
        
        # 거래 내역 기록 (시스템에서 사용자로)
        transaction_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO transactions (id, sender_id, receiver_id, amount, created_at) VALUES (?, ?, ?, ?, ?)",
            (transaction_id, session['user_id'], session['user_id'], amount, datetime.datetime.now())
        )
        
        db.commit()
        flash(f'{amount}원이 충전되었습니다.')
        return redirect(url_for('profile'))
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    
    return render_template('deposit.html', user=current_user)

# 채팅방 생성
@app.route('/chat/create/<product_id>')
@login_required
def create_chat(product_id):
    db = get_db()
    cursor = db.cursor()
    
    # 상품 정보 확인
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    if product['status'] != 'active':
        flash('해당 상품은 현재 거래할 수 없습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    
    if product['seller_id'] == session['user_id']:
        flash('자신의 상품에 대해 채팅을 시작할 수 없습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    
    # 이미 채팅방이 있는지 확인
    cursor.execute(
        "SELECT * FROM chat_room WHERE product_id = ? AND buyer_id = ? AND seller_id = ?",
        (product_id, session['user_id'], product['seller_id'])
    )
    existing_room = cursor.fetchone()
    
    if existing_room:
        return redirect(url_for('chat_room', room_id=existing_room['id']))
    
    # 새 채팅방 생성
    room_id = str(uuid.uuid4())
    cursor.execute(
        "INSERT INTO chat_room (id, product_id, buyer_id, seller_id, created_at) VALUES (?, ?, ?, ?, ?)",
        (room_id, product_id, session['user_id'], product['seller_id'], datetime.datetime.now())
    )
    db.commit()
    
    return redirect(url_for('chat_room', room_id=room_id))

# 채팅방 목록
@app.route('/chats')
@login_required
def chat_list():
    db = get_db()
    cursor = db.cursor()
    
    # 참여 중인 모든 채팅방 조회
    cursor.execute("""
        SELECT cr.*, 
               p.title as product_title, 
               p.price as product_price,
               p.status as product_status,
               s.username as seller_name,
               b.username as buyer_name
        FROM chat_room cr
        JOIN product p ON cr.product_id = p.id
        JOIN user s ON cr.seller_id = s.id
        JOIN user b ON cr.buyer_id = b.id
        WHERE cr.seller_id = ? OR cr.buyer_id = ?
        ORDER BY cr.created_at DESC
    """, (session['user_id'], session['user_id']))
    rooms = cursor.fetchall()
    
    return render_template('chat_list.html', rooms=rooms)

# 채팅방
@app.route('/chat/<room_id>')
@login_required
def chat_room(room_id):
    db = get_db()
    cursor = db.cursor()
    
    # 채팅방 정보 확인
    cursor.execute("""
        SELECT cr.*, 
               p.title as product_title, 
               p.price as product_price,
               p.status as product_status,
               p.id as product_id,
               s.username as seller_name,
               b.username as buyer_name
        FROM chat_room cr
        JOIN product p ON cr.product_id = p.id
        JOIN user s ON cr.seller_id = s.id
        JOIN user b ON cr.buyer_id = b.id
        WHERE cr.id = ?
    """, (room_id,))
    room = cursor.fetchone()
    
    if not room:
        flash('채팅방을 찾을 수 없습니다.')
        return redirect(url_for('chat_list'))
    
    # 사용자가 해당 채팅방에 참여 중인지 확인
    if room['seller_id'] != session['user_id'] and room['buyer_id'] != session['user_id']:
        flash('해당 채팅방에 접근할 권한이 없습니다.')
        return redirect(url_for('chat_list'))
    
    # 채팅 메시지 조회
    cursor.execute("""
        SELECT cm.*, u.username as sender_name
        FROM chat_message cm
        JOIN user u ON cm.sender_id = u.id
        WHERE cm.room_id = ?
        ORDER BY cm.created_at ASC
    """, (room_id,))
    messages = cursor.fetchall()
    
    is_seller = (room['seller_id'] == session['user_id'])
    other_user_id = room['buyer_id'] if is_seller else room['seller_id']
    
    return render_template('chat_room.html', room=room, messages=messages, is_seller=is_seller, other_user_id=other_user_id)

# 관리자 페이지 - 대시보드
@app.route('/admin')
@admin_required
def admin_dashboard():
    db = get_db()
    cursor = db.cursor()
    
    # 최근 가입 사용자 수
    cursor.execute("SELECT COUNT(*) as count FROM user WHERE created_at >= date('now', '-7 day')")
    new_users = cursor.fetchone()['count']
    
    # 최근 등록된 상품 수
    cursor.execute("SELECT COUNT(*) as count FROM product WHERE created_at >= date('now', '-7 day')")
    new_products = cursor.fetchone()['count']
    
    # 최근 완료된 거래 수
    cursor.execute("SELECT COUNT(*) as count FROM transactions WHERE created_at >= date('now', '-7 day')")
    new_transactions = cursor.fetchone()['count']
    
    # 처리 대기 중인 신고 수
    cursor.execute("SELECT COUNT(*) as count FROM report WHERE status = 'pending'")
    pending_reports = cursor.fetchone()['count']
    
    return render_template('admin_dashboard.html', 
                          new_users=new_users, 
                          new_products=new_products, 
                          new_transactions=new_transactions, 
                          pending_reports=pending_reports)

# 관리자 페이지 - 사용자 관리
@app.route('/admin/users')
@admin_required
def admin_users():
    db = get_db()
    cursor = db.cursor()
    
    # 모든 사용자 조회
    cursor.execute("SELECT * FROM user ORDER BY created_at DESC")
    users = cursor.fetchall()
    
    return render_template('admin_users.html', users=users)

# 관리자 페이지 - 사용자 상세
@app.route('/admin/user/<user_id>')
@admin_required
def admin_user_detail(user_id):
    db = get_db()
    cursor = db.cursor()
    
    # 사용자 정보
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('admin_users'))
    
    # 사용자가 등록한 상품
    cursor.execute("SELECT * FROM product WHERE seller_id = ? ORDER BY created_at DESC", (user_id,))
    products = cursor.fetchall()
    
    # 사용자 관련 거래 내역
    cursor.execute("""
        SELECT t.*, 
               s.username as sender_name, 
               r.username as receiver_name,
               p.title as product_title
        FROM transactions t
        JOIN user s ON t.sender_id = s.id
        JOIN user r ON t.receiver_id = r.id
        LEFT JOIN product p ON t.product_id = p.id
        WHERE t.sender_id = ? OR t.receiver_id = ?
        ORDER BY t.created_at DESC
    """, (user_id, user_id))
    transactions = cursor.fetchall()
    
    # 사용자 관련 신고 내역
    cursor.execute("""
        SELECT r.*, 
               ru.username as reporter_name, 
               tu.username as target_name
        FROM report r
        JOIN user ru ON r.reporter_id = ru.id
        JOIN user tu ON r.target_id = tu.id
        WHERE r.reporter_id = ? OR r.target_id = ?
        ORDER BY r.created_at DESC
    """, (user_id, user_id))
    reports = cursor.fetchall()
    
    return render_template('admin_user_detail.html', user=user, products=products, transactions=transactions, reports=reports)

# 불량 유저 휴면 기능 추가 부분
@app.route('/admin/user/<user_id>/suspend', methods=['POST'])
@admin_required
def suspend_user(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE user SET status = 'suspended' WHERE id = ?", (user_id,))
    db.commit()
    flash('사용자가 휴면 상태로 변경되었습니다.')
    return redirect(url_for('admin_user_detail', user_id=user_id))

# 데이터베이스 초기화 및 서버 실행
if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True)
