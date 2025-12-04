import sqlite3
import hashlib
from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = 'chave_super_secreta' # Necessário para mensagens de feedback

# --- CONFIGURAÇÃO DO BANCO ---
def get_db_connection():
    conn = sqlite3.connect('meu_banco.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    # Cria a tabela se não existir
    conn.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            login TEXT NOT NULL UNIQUE,
            senha_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# --- FUNÇÃO DE CRIPTOGRAFIA (HASH) ---
def criar_hash(senha_texto):
    # Transforma a senha (ex: "123") em Hash SHA-256
    return hashlib.sha256(senha_texto.encode('utf-8')).hexdigest()

# --- ROTAS DO SITE ---

@app.route('/')
def index():
    return redirect(url_for('login'))

# ROTA DE CADASTRO (INSERT)
@app.route('/cadastro', methods=('GET', 'POST'))
def cadastro():
    if request.method == 'POST':
        login_usuario = request.form['login']
        senha_texto = request.form['senha']

        # 1. Criptografa a senha ANTES de qualquer coisa
        senha_segura = criar_hash(senha_texto)

        conn = get_db_connection()
        try:
            # 2. Faz o INSERT no banco com a senha HASH
            conn.execute('INSERT INTO usuarios (login, senha_hash) VALUES (?, ?)',
                         (login_usuario, senha_segura))
            conn.commit()
            flash('Usuário cadastrado com sucesso! Agora faça login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Erro: Esse login já existe!')
        finally:
            conn.close()

    return render_template('cadastro.html')

# ROTA DE LOGIN (SELECT + COMPARAÇÃO)
@app.route('/login', methods=('GET', 'POST'))
def login():
    mensagem = None
    if request.method == 'POST':
        login_usuario = request.form['login']
        senha_texto = request.form['senha']

        conn = get_db_connection()
        # 3. Busca o usuário no banco (SELECT)
        usuario_db = conn.execute('SELECT * FROM usuarios WHERE login = ?', 
                                  (login_usuario,)).fetchone()
        conn.close()

        if usuario_db:
            # 4. Criptografa a senha que acabou de ser digitada
            hash_teste = criar_hash(senha_texto)
            
            # 5. Compara: Hash do Banco == Hash Digitado Agora?
            if usuario_db['senha_hash'] == hash_teste:
                return f"<h1>Sucesso!</h1> <p>Bem-vindo, {usuario_db['login']}.</p><p>Login realizado.</p>"
            else:
                mensagem = "Senha incorreta!"
        else:
            mensagem = "Usuário não encontrado!"

    return render_template('login.html', mensagem=mensagem)

# --- ROTA EXTRA (PARA PROVAR AO PROFESSOR QUE O HASH FUNCIONA) ---
@app.route('/ver-banco')
def ver_banco():
    conn = get_db_connection()
    usuarios = conn.execute('SELECT * FROM usuarios').fetchall()
    conn.close()
    
    # Monta uma lista simples em HTML para ver o que está salvo
    html = "<h2>Conteúdo do Banco de Dados (Prova do Hash)</h2><ul>"
    for usuario in usuarios:
        html += f"<li><strong>User:</strong> {usuario['login']} <br> <strong>Hash Salvo:</strong> {usuario['senha_hash']}</li><br>"
    html += "</ul><br><a href='/login'>Voltar</a>"
    return html

if __name__ == '__main__':
    init_db()
    app.run(debug=True)