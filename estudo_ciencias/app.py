import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy import or_ # Importação essencial para pesquisa OR

# --- Configurações Importantes ---
app = Flask(__name__)
# Configuração do banco de dados SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Chave Secreta para Sessões e Mensagens Flash
app.config['SECRET_KEY'] = 'chave_secreta_forte_para_sessoes_flash'
# Pasta onde os materiais de estudo serão salvos
app.config['UPLOAD_FOLDER'] = 'uploads'
# Extensões de arquivo permitidas no upload
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'mp4', 'mov', 'pdf', 'epub'} 

db = SQLAlchemy(app)

# --- Configurações do Administrador (Verificação Direta) ---
ADMIN_EMAIL = "melisiojorge@gmail.com"
PIN_CORRETO = "hercul1" # USADO PARA VERIFICAÇÃO DIRETA DO LOGIN ADMIN

# --- Modelo de Dados (Tabelas do Banco de Dados) ---

class Aluno(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    senha_hash = db.Column(db.String(250), nullable=False)

class Curso(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(50), unique=True, nullable=False)
    materiais = db.relationship('Material', backref='curso', lazy=True)

class Foco(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(50), unique=True, nullable=False)
    materiais = db.relationship('Material', backref='foco', lazy=True)

class Material(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(150), nullable=False)
    descricao = db.Column(db.Text, nullable=True)
    tipo = db.Column(db.String(10), nullable=False) # video, foto, livro
    filename = db.Column(db.String(200), nullable=False) # Nome do arquivo salvo
    curso_id = db.Column(db.Integer, db.ForeignKey('curso.id'), nullable=False)
    foco_id = db.Column(db.Integer, db.ForeignKey('foco.id'), nullable=False)

# --- Funções Auxiliares de Segurança e Rota ---

def allowed_file(filename):
    """Verifica se a extensão do arquivo é permitida."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def admin_required(f):
    """Decorator para proteger rotas de administrador."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session or not session['admin_logged_in']:
            flash('Acesso negado. Por favor, faça login de administrador.', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def aluno_required(f):
    """Decorator para proteger rotas de aluno."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'aluno_logged_in' not in session or not session['aluno_logged_in']:
            flash('Você precisa fazer login para acessar o conteúdo.', 'warning')
            return redirect(url_for('aluno_login'))
        return f(*args, **kwargs)
    return decorated_function


# Inicializa o Banco de Dados
with app.app_context():
    db.create_all()


# ==============================================================================
# 1. ROTAS DE AUTENTICAÇÃO E DASHBOARD (ADMIN)
# ==============================================================================

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email').strip()
        pin = request.form.get('pin').strip()
        
        # VERIFICAÇÃO DIRETA: garante que o login admin funcione sem falhas de hash
        if email == ADMIN_EMAIL and pin == PIN_CORRETO:
            session['admin_logged_in'] = True
            session['admin_email'] = email
            flash('Login de Admin realizado com sucesso!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Email ou PIN incorretos.', 'danger')
            return redirect(url_for('admin_login'))

    return render_template('admin_login.html', title="Login Admin")

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_email', None)
    flash('Você saiu da sua conta de administrador.', 'info')
    return redirect(url_for('index'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    cursos = Curso.query.count()
    materiais = Material.query.count()
    focos = Foco.query.count()
    alunos = Aluno.query.count()
    return render_template('admin_dashboard.html', title="Painel de Controle", 
                           cursos=cursos, materiais=materiais, focos=focos, alunos=alunos)

# ==============================================================================
# 2. ROTAS DE AUTENTICAÇÃO E DASHBOARD (ALUNO)
# ==============================================================================

@app.route('/cadastro', methods=['GET', 'POST'])
def aluno_cadastro():
    if request.method == 'POST':
        nome = request.form.get('nome')
        email = request.form.get('email').strip()
        senha = request.form.get('senha')
        
        if Aluno.query.filter_by(email=email).first():
            flash('Este email já está cadastrado. Tente fazer login.', 'warning')
            return redirect(url_for('aluno_cadastro'))
        
        # Usa hashing para a senha do aluno (segurança)
        hashed_password = generate_password_hash(senha, method='pbkdf2:sha256')
        
        novo_aluno = Aluno(nome=nome, email=email, senha_hash=hashed_password)
        db.session.add(novo_aluno)
        db.session.commit()
        
        session['aluno_logged_in'] = True
        session['aluno_id'] = novo_aluno.id
        session['aluno_nome'] = novo_aluno.nome
        
        flash('Cadastro realizado com sucesso! Bem-vindo(a) ao portal.', 'success')
        return redirect(url_for('aluno_dashboard'))
        
    return render_template('aluno_cadastro.html', title="Cadastre-se")

@app.route('/login', methods=['GET', 'POST'])
def aluno_login():
    if request.method == 'POST':
        email = request.form.get('email').strip()
        senha = request.form.get('senha')
        
        aluno = Aluno.query.filter_by(email=email).first()
        
        # Verifica a senha criptografada do aluno
        if aluno and check_password_hash(aluno.senha_hash, senha):
            session['aluno_logged_in'] = True
            session['aluno_id'] = aluno.id
            session['aluno_nome'] = aluno.nome
            flash(f'Bem-vindo(a) de volta, {aluno.nome}!', 'success')
            return redirect(url_for('aluno_dashboard'))
        else:
            flash('Email ou senha incorretos.', 'danger')
            return redirect(url_for('aluno_login'))
            
    return render_template('aluno_login.html', title="Login de Aluno")

@app.route('/aluno/logout')
def aluno_logout():
    session.pop('aluno_logged_in', None)
    session.pop('aluno_id', None)
    session.pop('aluno_nome', None)
    flash('Você saiu da sua conta.', 'info')
    return redirect(url_for('index'))

@app.route('/aluno/dashboard')
@aluno_required
def aluno_dashboard():
    return render_template('aluno_dashboard.html', title="Meu Painel")

# ==============================================================================
# 3. ROTAS DE NAVEGAÇÃO E PESQUISA PARA ALUNOS
# ==============================================================================

@app.route('/')
def index():
    cursos = Curso.query.all()
    # Puxa todos os Focos (categorias) para exibir na página inicial
    focos_principais = Foco.query.all()
    return render_template('index.html', cursos=cursos, focos_principais=focos_principais, title="Cursos Disponíveis")

@app.route('/curso/<int:curso_id>')
@aluno_required # Apenas alunos logados podem ver o conteúdo
def curso_detalhe(curso_id):
    curso = Curso.query.get_or_404(curso_id)
    
    materiais_do_curso = Material.query.filter_by(curso_id=curso_id).all()
    
    # Organiza os materiais por Foco (categoria/nível)
    materiais_organizados = {}
    focos_disponiveis = Foco.query.all()
    
    for foco in focos_disponiveis:
        materiais_do_foco = [m for m in materiais_do_curso if m.foco_id == foco.id]
        if materiais_do_foco:
            materiais_organizados[foco.nome] = materiais_do_foco
            
    return render_template(
        'curso_detalhe.html', 
        curso=curso, 
        materiais_organizados=materiais_organizados,
        title=curso.nome
    )

@app.route('/pesquisa')
@aluno_required 
def pesquisa():
    termo = request.args.get('termo', '').strip()
    resultados = []
    
    if termo:
        # Pesquisa em Título e Descrição dos Materiais (case insensitive)
        search_query = "%{}%".format(termo)
        resultados = Material.query.filter(or_(
            Material.titulo.ilike(search_query),
            Material.descricao.ilike(search_query)
        )).all()

    return render_template('pesquisa_resultados.html', 
                           termo=termo, 
                           resultados=resultados, 
                           title=f"Resultados para '{termo}'")


# Permite acesso direto aos arquivos da pasta 'uploads' (necessário para vídeos/pdfs)
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ==============================================================================
# 4. ROTAS DE ADMINISTRAÇÃO (Gerenciamento de Conteúdo)
# ==============================================================================

@app.route('/admin/cursos', methods=['GET', 'POST'])
@admin_required
def admin_cursos():
    if request.method == 'POST':
        novo_nome = request.form.get('nome')
        if novo_nome:
            if Curso.query.filter_by(nome=novo_nome).first():
                flash(f'O Curso "{novo_nome}" já existe!', 'warning')
            else:
                novo_curso = Curso(nome=novo_nome)
                db.session.add(novo_curso)
                db.session.commit()
                flash(f'Curso "{novo_nome}" adicionado com sucesso!', 'success')
        return redirect(url_for('admin_cursos'))
    
    cursos = Curso.query.all()
    return render_template('admin_cursos.html', cursos=cursos, title="Gerenciar Cursos")

@app.route('/admin/focos', methods=['GET', 'POST'])
@admin_required
def admin_focos():
    if request.method == 'POST':
        novo_nome = request.form.get('nome')
        if novo_nome:
            if Foco.query.filter_by(nome=novo_nome).first():
                flash(f'O Foco "{novo_nome}" já existe!', 'warning')
            else:
                novo_foco = Foco(nome=novo_nome)
                db.session.add(novo_foco)
                db.session.commit()
                flash(f'Foco "{novo_nome}" adicionado com sucesso!', 'success')
        return redirect(url_for('admin_focos'))
    
    focos = Foco.query.all()
    return render_template('admin_focos.html', focos=focos, title="Gerenciar Focos")

@app.route('/admin/upload', methods=['GET', 'POST'])
@admin_required
def admin_upload():
    cursos = Curso.query.all()
    focos = Foco.query.all()

    if request.method == 'POST':
        titulo = request.form.get('titulo')
        descricao = request.form.get('descricao')
        tipo = request.form.get('tipo')
        curso_id = request.form.get('curso_id')
        foco_id = request.form.get('foco_id')
        file = request.files.get('file')

        if not file or file.filename == '' or not allowed_file(file.filename):
            flash("Erro: Arquivo inválido, não selecionado ou tipo não permitido.", 'danger')
            return redirect(request.url)

        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Garante nome único para o arquivo
        base, ext = os.path.splitext(filename)
        counter = 1
        while os.path.exists(file_path):
            filename = f"{base}_{counter}{ext}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            counter += 1

        file.save(file_path)

        novo_material = Material(
            titulo=titulo, descricao=descricao, tipo=tipo, filename=filename,
            curso_id=curso_id, foco_id=foco_id
        )
        db.session.add(novo_material)
        db.session.commit()
        
        flash(f'Material "{titulo}" enviado com sucesso!', 'success')
        return redirect(url_for('admin_upload'))

    return render_template('admin_upload.html', cursos=cursos, focos=focos, title="Upload de Material")


# ==============================================================================
# 5. INICIALIZAÇÃO DO SERVIDOR
# ==============================================================================

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    app.run(debug=True)