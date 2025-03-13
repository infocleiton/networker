import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import paramiko
from cryptography.fernet import Fernet
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import re
from dotenv import load_dotenv
from ldap3 import Server, Connection, ALL, SUBTREE
from flask import jsonify

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')

if not app.secret_key:
    raise ValueError("A chave secreta (SECRET_KEY) não foi configurada. Defina a variável de ambiente SECRET_KEY.")

# Initialize security extensions
csrf = CSRFProtect(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
talisman = Talisman(
    app,
    force_https=False,  # Set to True in production
    strict_transport_security=True,
    session_cookie_secure=True,
    session_cookie_http_only=True,
    content_security_policy={
        'default-src': "'self'",
        'script-src': ["'self'", "'unsafe-inline'"],
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", "data:"]
    }
)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///firewalls.db'  # Banco de dados SQLite
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour CSRF token validity

# Extensões de arquivo permitidas
ALLOWED_EXTENSIONS = {'txt'}

# Arquivo de logs
LOG_FILE = 'logs.txt'

db = SQLAlchemy(app)

# Modelo para a tabela de firewalls
class Firewall(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)  # Nome do firewall
    ip = db.Column(db.String(15), nullable=False, unique=True)  # IP do firewall

# Modelo para a tabela de comandos
class Comando(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)  # Nome do conjunto de comandos
    comandos = db.Column(db.Text, nullable=False)  # Comandos (um por linha)

# Modelo para a tabela de switches
class Switch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)  # Nome do switch
    ip = db.Column(db.String(15), nullable=False, unique=True)  # IP do switch

# Modelo para a tabela de comandos de switches
class ComandoSwitch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)  # Nome do conjunto de comandos
    comandos = db.Column(db.Text, nullable=False)  # Comandos (um por linha)

# Funções auxiliares
def allowed_file(filename):
    """Verifica se o arquivo tem uma extensão permitida."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_key():
    return Fernet.generate_key()

def encrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data).decode()

def read_file(filename):
    try:
        with open(filename, 'r') as file:
            lines = file.read().splitlines()
            return [line.strip() for line in lines if not line.strip().startswith('#') and line.strip()]
    except Exception as e:
        log_message(f"Erro ao ler o arquivo {filename}: {e}")
        return None

def log_message(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, 'a') as log_file:
        log_file.write(f"[{timestamp}] {message}\n")
    print(message)

def is_valid_ip(ip):
    pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    return pattern.match(ip) is not None

def _xeccoe(hsh_commds(hosnam,port, am,psswor,mmads):
    lryamiko.SSHClient()
        cliltt.= paramsko.SSHClieem()ng_host_key_policy(paramiko.AutoAddPolicy())
     nn cl e s.sethmiesing_hosl_kly_policy.paiamko.AoAddPolicy()
   client.connect(hotnme, port=ort, usernam=urnme,psswod=psswod)
        Ahellardclae s.invokeeghslp c
arregar as informações iniciais
        # Ag a.das5esegupdos (ara o wich cagar as informçõsiniciais
  tme.le5

        for command in commands:
            log_message(f"Executando comando no {hostname}: {command}")
            shell.send(command + '\n')
            output = ""
            while True:
                if shell.recv_ready():
                    part = shell.recv(4096).decode('utf-8', errors='replace')
                    output += part
                    print(part, end="")
                else:
                    if ">" in output or "#" in output:
                        break
                    time.sleep(0.1)

            log_message("Saída do comando:")
            log_message(output.strip())
            log_message("-" * 50)

        client.close()
        log_message(f"Conexão SSH com {hostname} fechada.")
        return True, None  # Sucesso, sem erro
    except paramiko.ssh_exception.AuthenticationException:
        error_message = f"Falha na autenticação com o servidor {hostname}."
        log_message(error_message)
        return False, error_message  # Falha, com mensagem de erro
    except Exception as e:
        error_message = f"Erro ao conectar ou executar comandos em {hostname}: {e}"
        log_message(error_message)
        return False, error_message  # Falha, com mensagem de erro

# Autenticação no Active Directory
def autenticar_ad(username, password):
    # Configurações do AD
    AD_SERVER = 'ldap://gowacd10.pratika.br'  # Substitua pelo endereço do seu AD
    AD_DOMAIN = 'pratika.br'  # Substitua pelo seu domínio
    BASE_DN = 'DC=pratika,DC=br'  # Substitua pelo Base DN do seu AD
    ADMIN_GROUP = 'CN=Digital - Telecomunicações Dados,OU=Grupos,DC=pratika,DC=br'  # Grupo de administradores
    OPERATOR_GROUP = 'CN=Digital - Operação,OU=Hypera,OU=Grupos,DC=pratika,DC=br'  # Grupo de operadores

    try:
        # Conecta ao servidor LDAP
        server = Server(AD_SERVER, get_info=ALL)
        conn = Connection(server, user=f"{username}@{AD_DOMAIN}", password=password, auto_bind=True)

        # Busca o usuário no AD
        conn.search(BASE_DN, f"(sAMAccountName={username})", attributes=['memberOf'])

        if not conn.entries:
            return False, "Usuário não encontrado no AD."

        # Verifica os grupos do usuário
        user_groups = conn.entries[0].memberOf.values
        is_admin = any(ADMIN_GROUP in group for group in user_groups)
        is_operator = any(OPERATOR_GROUP in group for group in user_groups)

        if not (is_admin or is_operator):
            return False, "Usuário não pertence a nenhum grupo permitido."

        # Retorna o perfil do usuário
        perfil = "admin" if is_admin else "operator"
        return True, perfil

    except Exception as e:
        return False, f"Erro ao autenticar no AD: {str(e)}"

# Rotas da aplicação
@app.route('/', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def index():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Verifica se o formulário de execução de comandos para switches foi enviado
        if 'switches' in request.form:
            # Obtém os switches selecionados
            selected_switches = request.form.getlist('switches')
            if not selected_switches:
                flash('Selecione pelo menos um switch.')
                return redirect(url_for('index'))

            # Obtém as credenciais
            username = request.form['username_switch']
            password = request.form['password_switch']

            # Obtém os comandos selecionados
            comandos_switch = request.form['comandos_switch'].splitlines()  # Divide os comandos por linha
            if not comandos_switch:
                flash('Nenhum comando selecionado.')
                return redirect(url_for('index'))

            # Executa os comandos nos switches selecionados
            erros = []
            with ThreadPoolExecutor(max_workers=5) as executor:
                resultados = list(executor.map(
                    lambda ip: execute_ssh_commands(ip, 22, username, password, comandos_switch),
                    selected_switches
                ))

                # Verifica se houve erros
                for ip, (sucesso, erro) in zip(selected_switches, resultados):
                    if not sucesso:
                        erros.append(f"Erro no switch {ip}: {erro}")

            if erros:
                # Se houver erros, exibe todas as mensagens de erro
                for erro in erros:
                    flash(erro)
            else:
                # Se não houver erros, exibe mensagem de sucesso
                flash('Comandos executados com sucesso!')

            return redirect(url_for('index'))

    # Lista todos os firewalls, switches e comandos cadastrados
    firewalls = Firewall.query.all()
    comandos = Comando.query.all()
    switches = Switch.query.all()
    comandos_switch = ComandoSwitch.query.all()
    return render_template('index.html', firewalls=firewalls, comandos=comandos, switches=switches, comandos_switch=comandos_switch)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Autentica no AD
        sucesso, mensagem = autenticar_ad(username, password)

        if sucesso:
            # Armazena o perfil do usuário na sessão
            session['username'] = username
            session['perfil'] = mensagem  # 'admin' ou 'operator'
            flash('Login realizado com sucesso!')
            return redirect(url_for('index'))
        else:
            flash(mensagem)  # Exibe mensagem de erro
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logout realizado com sucesso!')
    return redirect(url_for('login'))

@app.route('/cadastrar', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def cadastrar():
    if 'perfil' not in session or session['perfil'] != 'admin':
        flash('Acesso negado. Somente administradores podem acessar esta página.')
        return redirect(url_for('index'))

    if request.method == 'POST':
        # Verifica se o formulário de cadastro foi enviado
        if 'nome' in request.form and 'ip' in request.form:
            nome = request.form['nome']
            ip = request.form['ip']

            # Validações
            if not nome or not ip:
                flash('Preencha todos os campos.')
                return redirect(url_for('cadastrar'))

            if not is_valid_ip(ip):
                flash('IP inválido.')
                return redirect(url_for('cadastrar'))

            # Verifica se o IP já está cadastrado
            if Firewall.query.filter_by(ip=ip).first():
                flash('IP já cadastrado.')
                return redirect(url_for('cadastrar'))

            # Adiciona o novo firewall ao banco de dados
            novo_firewall = Firewall(nome=nome, ip=ip)
            db.session.add(novo_firewall)
            db.session.commit()
            flash('Firewall cadastrado com sucesso!')
            return redirect(url_for('cadastrar'))

    # Lista todos os firewalls cadastrados
    firewalls = Firewall.query.all()
    return render_template('cadastrar.html', firewalls=firewalls)

@app.route('/editar_firewall/<int:id>', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def editar_firewall(id):
    if 'perfil' not in session or session['perfil'] != 'admin':
        flash('Acesso negado. Somente administradores podem acessar esta página.')
        return redirect(url_for('index'))

    firewall = Firewall.query.get_or_404(id)

    if request.method == 'POST':
        nome = request.form['nome']
        ip = request.form['ip']

        if not nome or not ip:
            flash('Preencha todos os campos.')
            return redirect(url_for('editar_firewall', id=id))

        if not is_valid_ip(ip):
            flash('IP inválido.')
            return redirect(url_for('editar_firewall', id=id))

        # Verifica se o IP já está em uso por outro firewall
        if Firewall.query.filter(Firewall.id != id, Firewall.ip == ip).first():
            flash('IP já cadastrado.')
            return redirect(url_for('editar_firewall', id=id))

        firewall.nome = nome
        firewall.ip = ip
        db.session.commit()
        flash('Firewall atualizado com sucesso!')
        return redirect(url_for('cadastrar'))

    return render_template('editar_firewall.html', firewall=firewall)

@app.route('/excluir', methods=['POST'])
def excluir():
    if 'perfil' not in session or session['perfil'] != 'admin':
        flash('Acesso negado. Somente administradores podem acessar esta página.')
        return redirect(url_for('index'))

    # Obtém os IDs dos firewalls selecionados
    selected_firewalls = request.form.getlist('firewalls')
    if not selected_firewalls:
        flash('Nenhum firewall selecionado para exclusão.')
        return redirect(url_for('cadastrar'))

    # Exclui cada firewall selecionado
    for firewall_id in selected_firewalls:
        firewall = Firewall.query.get_or_404(firewall_id)
        db.session.delete(firewall)
    db.session.commit()

    flash('Firewalls excluídos com sucesso!')
    return redirect(url_for('cadastrar'))

@app.route('/cadastrar_comandos', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def cadastrar_comandos():
    if 'perfil' not in session or session['perfil'] != 'admin':
        flash('Acesso negado. Somente administradores podem acessar esta página.')
        return redirect(url_for('index'))

    if request.method == 'POST':
        # Verifica se o formulário de cadastro foi enviado
        if 'nome' in request.form and 'comandos' in request.form:
            nome = request.form['nome']
            comandos = request.form['comandos']

            # Validações
            if not nome or not comandos:
                flash('Preencha todos os campos.')
                return redirect(url_for('cadastrar_comandos'))

            # Verifica se o nome já está cadastrado
            if Comando.query.filter_by(nome=nome).first():
                flash('Nome já cadastrado.')
                return redirect(url_for('cadastrar_comandos'))

            # Adiciona o novo conjunto de comandos ao banco de dados
            novo_comando = Comando(nome=nome, comandos=comandos)
            db.session.add(novo_comando)
            db.session.commit()
            flash('Conjunto de comandos cadastrado com sucesso!')
            return redirect(url_for('cadastrar_comandos'))

    # Lista todos os conjuntos de comandos cadastrados
    comandos = Comando.query.all()
    return render_template('cadastrar_comandos.html', comandos=comandos)

@app.route('/editar_comando/<int:id>', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def editar_comando(id):
    if 'perfil' not in session or session['perfil'] != 'admin':
        flash('Acesso negado. Somente administradores podem acessar esta página.')
        return redirect(url_for('index'))

    comando = Comando.query.get_or_404(id)

    if request.method == 'POST':
        nome = request.form['nome']
        comandos = request.form['comandos']

        if not nome or not comandos:
            flash('Preencha todos os campos.')
            return redirect(url_for('editar_comando', id=id))

        # Verifica se o nome já está em uso por outro comando
        if Comando.query.filter(Comando.id != id, Comando.nome == nome).first():
            flash('Nome já cadastrado.')
            return redirect(url_for('editar_comando', id=id))

        comando.nome = nome
        comando.comandos = comandos
        db.session.commit()
        flash('Comando atualizado com sucesso!')
        return redirect(url_for('cadastrar_comandos'))

    return render_template('editar_comando.html', comando=comando)

@app.route('/excluir_comandos', methods=['POST'])
def excluir_comandos():
    if 'perfil' not in session or session['perfil'] != 'admin':
        flash('Acesso negado. Somente administradores podem acessar esta página.')
        return redirect(url_for('index'))

    # Obtém os IDs dos conjuntos de comandos selecionados
    selected_comandos = request.form.getlist('comandos')
    if not selected_comandos:
        flash('Nenhum conjunto de comandos selecionado para exclusão.')
        return redirect(url_for('cadastrar_comandos'))

    # Exclui cada conjunto de comandos selecionado
    for comando_id in selected_comandos:
        comando = Comando.query.get_or_404(comando_id)
        db.session.delete(comando)
    db.session.commit()

    flash('Conjuntos de comandos excluídos com sucesso!')
    return redirect(url_for('cadastrar_comandos'))

@app.route('/cadastrar_switch', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def cadastrar_switch():
    if 'perfil' not in session or session['perfil'] != 'admin':
        flash('Acesso negado. Somente administradores podem acessar esta página.')
        return redirect(url_for('index'))

    if request.method == 'POST':
        # Verifica se o formulário de cadastro foi enviado
        if 'nome' in request.form and 'ip' in request.form:
            nome = request.form['nome']
            ip = request.form['ip']

            # Validações
            if not nome or not ip:
                flash('Preencha todos os campos.')
                return redirect(url_for('cadastrar_switch'))

            if not is_valid_ip(ip):
                flash('IP inválido.')
                return redirect(url_for('cadastrar_switch'))

            # Verifica se o IP já está cadastrado
            if Switch.query.filter_by(ip=ip).first():
                flash('IP já cadastrado.')
                return redirect(url_for('cadastrar_switch'))

            # Adiciona o novo switch ao banco de dados
            novo_switch = Switch(nome=nome, ip=ip)
            db.session.add(novo_switch)
            db.session.commit()
            flash('Switch cadastrado com sucesso!')
            return redirect(url_for('cadastrar_switch'))

    # Lista todos os switches cadastrados
    switches = Switch.query.all()
    return render_template('cadastrar_switch.html', switches=switches)

@app.route('/editar_switch/<int:id>', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def editar_switch(id):
    if 'perfil' not in session or session['perfil'] != 'admin':
        flash('Acesso negado. Somente administradores podem acessar esta página.')
        return redirect(url_for('index'))

    switch = Switch.query.get_or_404(id)

    if request.method == 'POST':
        nome = request.form['nome']
        ip = request.form['ip']

        if not nome or not ip:
            flash('Preencha todos os campos.')
            return redirect(url_for('editar_switch', id=id))

        if not is_valid_ip(ip):
            flash('IP inválido.')
            return redirect(url_for('editar_switch', id=id))

        # Verifica se o IP já está em uso por outro switch
        if Switch.query.filter(Switch.id != id, Switch.ip == ip).first():
            flash('IP já cadastrado.')
            return redirect(url_for('editar_switch', id=id))

        switch.nome = nome
        switch.ip = ip
        db.session.commit()
        flash('Switch atualizado com sucesso!')
        return redirect(url_for('cadastrar_switch'))

    return render_template('editar_switch.html', switch=switch)

@app.route('/excluir_switch', methods=['POST'])
def excluir_switch():
    if 'perfil' not in session or session['perfil'] != 'admin':
        flash('Acesso negado. Somente administradores podem acessar esta página.')
        return redirect(url_for('index'))

    # Obtém os IDs dos switches selecionados
    selected_switches = request.form.getlist('switches')
    if not selected_switches:
        flash('Nenhum switch selecionado para exclusão.')
        return redirect(url_for('cadastrar_switch'))

    # Exclui cada switch selecionado
    for switch_id in selected_switches:
        switch = Switch.query.get_or_404(switch_id)
        db.session.delete(switch)
    db.session.commit()

    flash('Switches excluídos com sucesso!')
    return redirect(url_for('cadastrar_switch'))

@app.route('/cadastrar_comandos_switch', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def cadastrar_comandos_switch():
    if 'perfil' not in session or session['perfil'] != 'admin':
        flash('Acesso negado. Somente administradores podem acessar esta página.')
        return redirect(url_for('index'))

    if request.method == 'POST':
        # Verifica se o formulário de cadastro foi enviado
        if 'nome' in request.form and 'comandos' in request.form:
            nome = request.form['nome']
            comandos = request.form['comandos']

            # Validações
            if not nome or not comandos:
                flash('Preencha todos os campos.')
                return redirect(url_for('cadastrar_comandos_switch'))

            # Verifica se o nome já está cadastrado
            if ComandoSwitch.query.filter_by(nome=nome).first():
                flash('Nome já cadastrado.')
                return redirect(url_for('cadastrar_comandos_switch'))

            # Adiciona o novo conjunto de comandos ao banco de dados
            novo_comando = ComandoSwitch(nome=nome, comandos=comandos)
            db.session.add(novo_comando)
            db.session.commit()
            flash('Conjunto de comandos cadastrado com sucesso!')
            return redirect(url_for('cadastrar_comandos_switch'))

    # Lista todos os conjuntos de comandos cadastrados
    comandos_switch = ComandoSwitch.query.all()
    return render_template('cadastrar_comandos_switch.html', comandos_switch=comandos_switch)

@app.route('/editar_comando_switch/<int:id>', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def editar_comando_switch(id):
    if 'perfil' not in session or session['perfil'] != 'admin':
        flash('Acesso negado. Somente administradores podem acessar esta página.')
        return redirect(url_for('index'))

    comando = ComandoSwitch.query.get_or_404(id)

    if request.method == 'POST':
        nome = request.form['nome']
        comandos = request.form['comandos']

        if not nome or not comandos:
            flash('Preencha todos os campos.')
            return redirect(url_for('editar_comando_switch', id=id))

        # Verifica se o nome já está em uso por outro comando
        if ComandoSwitch.query.filter(ComandoSwitch.id != id, ComandoSwitch.nome == nome).first():
            flash('Nome já cadastrado.')
            return redirect(url_for('editar_comando_switch', id=id))

        comando.nome = nome
        comando.comandos = comandos
        db.session.commit()
        flash('Comando atualizado com sucesso!')
        return redirect(url_for('cadastrar_comandos_switch'))

    return render_template('editar_comando_switch.html', comando=comando)

@app.route('/excluir_comandos_switch', methods=['POST'])
def excluir_comandos_switch():
    if 'perfil' not in session or session['perfil'] != 'admin':
        flash('Acesso negado. Somente administradores podem acessar esta página.')
        return redirect(url_for('index'))

    # Obtém os IDs dos conjuntos de comandos selecionados
    selected_comandos = request.form.getlist('comandos')
    if not selected_comandos:
        flash('Nenhum conjunto de comandos selecionado para exclusão.')
        return redirect(url_for('cadastrar_comandos_switch'))

    # Exclui cada conjunto de comandos selecionado
    for comando_id in selected_comandos:
        comando = ComandoSwitch.query.get_or_404(comando_id)
        db.session.delete(comando)
    db.session.commit()

    flash('Conjuntos de comandos excluídos com sucesso!')
    return redirect(url_for('cadastrar_comandos_switch'))

@app.route('/logs')
def logs():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Lê o conteúdo do arquivo de logs
    with open(LOG_FILE, 'r') as log_file:
        logs_content = log_file.readlines()

    # Inverte a ordem dos logs (mais recentes primeiro)
    logs_content.reverse()

    return render_template('logs.html', logs=logs_content)

@app.route('/limpar_logs', methods=['POST'])
def limpar_logs():
    if 'username' not in session or session.get('perfil') != 'admin':
        return jsonify({"success": False, "message": "Acesso negado."}), 403

    try:
        # Abre o arquivo de logs em modo de escrita para limpar o conteúdo
        with open(LOG_FILE, 'w') as log_file:
            log_file.write("")  # Limpa o conteúdo do arquivo

        # Retorna uma resposta JSON de sucesso
        return jsonify({"success": True, "message": "Logs limpos com sucesso!"}), 200
    except Exception as e:
        # Retorna uma resposta JSON de erro
        return jsonify({"success": False, "message": f"Erro ao limpar logs: {str(e)}"}), 500

if __name__ == '__main__':
    # Cria o banco de dados e a pasta de uploads se não existirem
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    with app.app_context():
        db.create_all()
    app.run(debug=True)
