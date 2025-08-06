from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import sqlite3
from datetime import datetime, timedelta
import subprocess
import json
import os
import socket
import logging
from dateutil.relativedelta import relativedelta
from contextlib import closing
from functools import lru_cache
from flask_cors import CORS
from threading import Thread

# Configuración inicial
app = Flask(__name__)
CORS(app)  # Esto permite CORS desde cualquier origen

DB_PATH = '/home/rud1/web_panel/data/sensor_data.db'
DB_TIMEOUT = 30
DB_PRAGMAS = {
    'journal_mode': 'WAL',
    'cache_size': -10000,
    'synchronous': 'NORMAL'
}

ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'maes2admin')

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/rud1/web_panel/logs/web_panel.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuración de la aplicación
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '1234567890abcdef')
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

@app.context_processor
def utility_processor():
    return dict(get_machine_name=get_machine_name)

# Helpers de base de datos
def get_db_connection():
    """Obtiene una conexión a la base de datos con configuraciones optimizadas"""
    conn = sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT)
    for pragma, value in DB_PRAGMAS.items():
        conn.execute(f'PRAGMA {pragma}={value}')
    return conn

def ensure_indexes():
    """Crea índices necesarios para optimizar consultas"""
    with closing(get_db_connection()) as conn:
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sensor_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                value REAL NOT NULL,
                timestamp DATETIME NOT NULL
            )
        """)
        
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp 
            ON sensor_data(timestamp)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_date 
            ON sensor_data(DATE(timestamp))
        """)
        conn.commit()

# Comandos del sistema
def execute_command(command, timeout=15):
    """Ejecuta comandos del sistema con manejo robusto de errores"""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True
        )
        return {'success': True, 'output': result.stdout}
    except subprocess.TimeoutExpired:
        return {'success': False, 'error': 'Timeout expired'}
    except subprocess.CalledProcessError as e:
        return {'success': False, 'error': e.stderr}
    except Exception as e:
        return {'success': False, 'error': str(e)}

# Rutas principales
@app.route('/')
def index():
    limit = request.args.get("limit", "10")
    date_filter = request.args.get("date")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    query = "SELECT value, timestamp FROM sensor_data"
    params = []

    if date_filter:
        query += " WHERE date(timestamp) = ?"
        params.append(date_filter)

    query += " ORDER BY timestamp DESC"
    if limit != "all":
        query += " LIMIT ?"
        params.append(int(limit))

    c.execute(query, params)
    rows = c.fetchall()
    data = [{"value": row[0], "timestamp": row[1]} for row in rows]

    conn.close()
    return render_template("index.html", data=data)

# API de datos
@app.route('/api/sensor/data', methods=['GET'])
def api_sensor_data():
    limit = request.args.get("limit", "10")
    date_filter = request.args.get("date")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    query = "SELECT value, timestamp FROM sensor_data"
    params = []

    if date_filter:
        query += " WHERE date(timestamp) = ?"
        params.append(date_filter)

    query += " ORDER BY timestamp DESC"
    if limit != "all":
        query += " LIMIT ?"
        params.append(int(limit))

    c.execute(query, params)
    rows = c.fetchall()
    data = [{"value": row[0], "timestamp": row[1]} for row in rows]

    # Calcular diferencias
    if date_filter and len(data) >= 2:
        timestamps = [datetime.strptime(d["timestamp"], "%Y-%m-%d %H:%M:%S") for d in data]
        diffs = [(timestamps[i] - timestamps[i + 1]).total_seconds() for i in range(len(timestamps) - 1)]
        avg_diff = sum(diffs) / len(diffs)
    else:
        avg_diff = None

    conn.close()
    return jsonify({"data": data, "avg_diff": avg_diff})

# Estadísticas y resúmenes
def get_cached_daily_stats(month, year):
    """Obtiene estadísticas diarias con caché"""
    try:
        ensure_indexes()
        with closing(get_db_connection()) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    DATE(timestamp) as day,
                    COUNT(*) as count,
                    MAX(value) as max_value,
                    AVG(value) as average
                FROM sensor_data
                WHERE strftime('%m', timestamp) = ?
                  AND strftime('%Y', timestamp) = ?
                GROUP BY day
                ORDER BY day DESC
            """, (f"{month:02d}", str(year)))
            
            columns = [col[0] for col in cursor.description]
            return [dict(zip(columns, row)) for row in cursor]
    except Exception as e:
        logger.error(f"Error en get_cached_daily_stats: {str(e)}")
        return []

def get_machine_name():
    host = request.host  # Obtiene el dominio completo
    machine_names = {
        'disp00.rud1.es': 'Prensa Pequeña',
        'disp01.rud1.es': 'Imabe',
        'disp02.rud1.es': 'Jovisa'
    }
    
    # Extraer solo el subdominio principal
    domain_parts = host.split('.')
    if len(domain_parts) > 2:
        subdomain = domain_parts[0]
        full_domain = f"{subdomain}.rud1.es"
    else:
        full_domain = host
    
    return machine_names.get(full_domain, 'Máquina Contador')

@app.route('/api/sensor/daily_stats', methods=['GET'])
def get_daily_stats():
    date_filter = request.args.get("date")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    if date_filter:
        c.execute("SELECT value, timestamp FROM sensor_data WHERE date(timestamp) = ? ORDER BY timestamp ASC", (date_filter,))
        rows = c.fetchall()
        if rows:
            values = [r[0] for r in rows]
            timestamps = [datetime.strptime(r[1], "%Y-%m-%d %H:%M:%S") for r in rows]
            diffs = [(timestamps[i] - timestamps[i - 1]).total_seconds() for i in range(1, len(timestamps))]
            avg_diff = sum(diffs) / len(diffs) if diffs else 0
            result = [{
                "day": date_filter,
                "count": len(values),
                "average": round(sum(values) / len(values), 2),
                "max_value": max(values),
                "avg_diff": round(avg_diff, 2)
            }]
        else:
            result = []
    else:
        c.execute("SELECT date(timestamp), COUNT(*), AVG(value), MAX(value) FROM sensor_data GROUP BY date(timestamp)")
        rows = c.fetchall()
        result = []
        for day, count, avg, max_val in rows:
            c.execute("SELECT timestamp FROM sensor_data WHERE date(timestamp) = ? ORDER BY timestamp ASC", (day,))
            ts_rows = c.fetchall()
            timestamps = [datetime.strptime(r[0], "%Y-%m-%d %H:%M:%S") for r in ts_rows]
            diffs = [(timestamps[i] - timestamps[i - 1]).total_seconds() for i in range(1, len(timestamps))]
            avg_diff = sum(diffs) / len(diffs) if diffs else 0
            result.append({
                "day": day,
                "count": count,
                "average": round(avg, 2),
                "max_value": max_val,
                "avg_diff": round(avg_diff, 2)
            })

    conn.close()
    return jsonify(result)

# Configuración WiFi
@app.route('/config', methods=['GET', 'POST'])
def wifi_config():
    """Página de configuración WiFi"""
    if request.method == 'POST':
        ssid = request.form.get('ssid')
        password = request.form.get('password')
        
        if not ssid:
            return render_template('config.html', 
                                message="Error: SSID requerido",
                                wifi_networks=get_wifi_networks(),
                                current_ssid=get_current_wifi())
        
        # Intento de conexión
        result = connect_to_wifi(ssid, password)
        
        return render_template('config.html', 
                            message=result['message'],
                            wifi_networks=get_wifi_networks(),
                            current_ssid=get_current_wifi())
    
    return render_template('config.html',
                         wifi_networks=get_wifi_networks(),
                         current_ssid=get_current_wifi())

def connect_to_wifi(ssid, password=None):
    """Intenta conectar a una red WiFi"""
    # Primer intento - conexión directa
    cmd = ['nmcli', 'device', 'wifi', 'connect', ssid]
    if password:
        cmd.extend(['password', password])
    
    result = execute_command(cmd)
    
    if not result['success'] and '802-11-wireless-security.key-mgmt' in result.get('error', ''):
        # Segundo intento - método alternativo
        execute_command(['nmcli', 'con', 'delete', ssid])
        
        alt_cmd = [
            'nmcli', 'con', 'add',
            'type', 'wifi',
            'con-name', ssid,
            'ifname', 'wlan0',
            'ssid', ssid,
            'wifi-sec.key-mgmt', 'wpa-psk'
        ]
        
        if password:
            alt_cmd.extend(['wifi-sec.psk', password])
        
        result = execute_command(alt_cmd)
        
        if result['success']:
            result = execute_command(['nmcli', 'con', 'up', ssid])
    
    return {
        'success': result['success'],
        'message': f"Conectado a {ssid}" if result['success'] else f"Error: {result.get('error', 'Desconocido')}"
    }

@app.route('/api/wifi/networks', methods=['GET'])
def networks():
    return get_wifi_networks()

def get_wifi_networks():
    """Obtiene listado de redes WiFi disponibles"""
    try:
        result = execute_command(['nmcli', '-f', 'SSID,SIGNAL,SECURITY', '-t', 'dev', 'wifi', 'list'])
        if not result['success']:
            return []
        
        networks = []
        seen = set()
        
        for line in result['output'].split('\n'):
            if line.strip():
                parts = line.split(':')
                if len(parts) >= 3 and parts[0] and parts[0] not in seen:
                    seen.add(parts[0])
                    security = parts[2] if parts[2] else 'Abierta'
                    if 'WPA2' in security:
                        security = 'WPA2'
                    elif 'WPA' in security:
                        security = 'WPA'
                    elif 'WEP' in security:
                        security = 'WEP'
                    
                    networks.append({
                        'ssid': parts[0],
                        'signal': parts[1],
                        'security': security
                    })
        
        return sorted(networks, key=lambda x: int(x['signal']), reverse=True)
    except Exception as e:
        logger.error(f"Error en get_wifi_networks: {str(e)}")
        return []

def get_current_wifi():
    """Obtiene la red WiFi actualmente conectada"""
    try:
        result = execute_command(['nmcli', '-t', '-f', 'ACTIVE,SSID', 'dev', 'wifi'])
        if result['success']:
            for line in result['output'].split('\n'):
                if line.startswith('Sí:'):
                    return line.split(':')[1]
        
        result = execute_command(['nmcli', '-t', '-f', 'NAME,DEVICE,TYPE,STATE', 'con', 'show', '--active'])
        if result['success']:
            for line in result['output'].split('\n'):
                if 'wifi' in line and 'activated' in line:
                    conn_name = line.split(':')[0]
                    detail = execute_command(['nmcli', '-t', '-f', '802-11-wireless.ssid', 'con', 'show', conn_name])
                    if detail['success']:
                        return detail['output'].split(':')[0]
        
        return "No conectado"
    except Exception as e:
        logger.error(f"Error en get_current_wifi: {str(e)}")
        return "Desconocido"

#Panel de administración
@app.route('/admin', methods=['GET', 'POST'])
def admin_panel():
    try:
        if request.method == 'POST':
            if not session.get('admin_logged_in'):
                password = request.form.get('admin_password')
                if password == ADMIN_PASSWORD:
                    session['admin_logged_in'] = True
                else:
                    return render_template('admin.html', message='Contraseña incorrecta')
            else:
                action = request.form.get('action')
                message = ""

                if action == 'reboot':
                    result = execute_command(['sudo', 'reboot'])
                    message = "Reiniciando..." if result['success'] else f"Error: {result.get('error', 'Desconocido')}"

                elif action == 'clear_db':
                    try:
                        with closing(get_db_connection()) as conn:
                            conn.execute("DELETE FROM sensor_data")
                            conn.commit()
                        message = "Base de datos borrada"
                    except Exception as e:
                        message = f"Error al borrar datos: {str(e)}"

                elif action == 'update_system':
                    try:
                        update_script = '/home/rud1/scripts/update_system.sh'
                        if not os.path.exists(update_script):
                            message = "Error: Script de actualización no encontrado"
                        else:
                            def run_update():
                                subprocess.Popen([
                                    'sudo', 'nohup', update_script,
                                    '>/tmp/update.log', '2>/tmp/update_error.log', '&'
                                ], preexec_fn=os.setpgrp)
                            Thread(target=run_update).start()
                            message = "Actualización iniciada. El sistema se reiniciará cuando termine."
                    except Exception as e:
                        message = f"Error al iniciar actualización: {str(e)}"

                with closing(get_db_connection()) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT COUNT(*) FROM sensor_data")
                    count = cursor.fetchone()[0]
                    cursor.execute("SELECT value, timestamp FROM sensor_data ORDER BY timestamp DESC LIMIT 1")
                    last_record = cursor.fetchone()

                return render_template('admin.html', message=message, count=count, last_record=last_record)

        if not session.get('admin_logged_in'):
            return render_template('admin.html')

        with closing(get_db_connection()) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM sensor_data")
            count = cursor.fetchone()[0]
            cursor.execute("SELECT value, timestamp FROM sensor_data ORDER BY timestamp DESC LIMIT 1")
            last_record = cursor.fetchone()

        return render_template('admin.html', count=count, last_record=last_record)

    except Exception as e:
        logger.error(f"Error en admin_panel: {str(e)}")
        return render_template('error.html', message="Error en el panel de administración"), 500

# Ruta para cerrar sesión de admin
@app.route('/logout_admin')
def logout_admin():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_panel'))

# Calendario de datos
@app.route('/calendar')
def calendar_view():
    """Vista de calendario con resúmenes mensuales"""
    try:
        month = int(request.args.get('month', datetime.now().month))
        year = int(request.args.get('year', datetime.now().year))
        
        current_month = datetime(year, month, 1)
        prev_month = current_month - relativedelta(months=1)
        next_month = current_month + relativedelta(months=1)
        
        daily_totals = get_cached_daily_stats(month, year)
        
        # Resumen mensual
        total_count = sum(day['count'] for day in daily_totals) if daily_totals else 0
        max_value = max((day['max_value'] for day in daily_totals), default=0)
        daily_avg = sum(day['average'] for day in daily_totals) / len(daily_totals) if daily_totals else 0
        
        return render_template('calendar.html',
                            daily_totals=daily_totals,
                            monthly_summary={
                                'total_count': total_count,
                                'max_value': max_value,
                                'daily_avg': daily_avg
                            },
                            current_month=current_month.strftime("%B %Y"),
                            prev_month={
                                'month': prev_month.month,
                                'year': prev_month.year,
                                'text': prev_month.strftime("%B")
                            },
                            next_month={
                                'month': next_month.month,
                                'year': next_month.year,
                                'text': next_month.strftime("%B")
                            })
    except Exception as e:
        logger.error(f"Error en calendar_view: {str(e)}")
        return render_template('error.html', message="Error al cargar el calendario"), 500

# API de sistema
@app.route('/api/system/info', methods=['GET'])
def system_info():
    """API para obtener información del sistema"""
    try:
        # WiFi
        wifi_ssid = get_current_wifi()
        
        # IP
        ip_address = "Desconocida"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
            s.close()
        except Exception:
            pass
        
        # Última lectura
        with closing(get_db_connection()) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value, timestamp FROM sensor_data ORDER BY timestamp DESC LIMIT 1")
            last = cursor.fetchone()
        
        return jsonify({
            'wifi_ssid': wifi_ssid,
            'ip_address': ip_address,
            'last_reading': {
                'value': last[0],
                'timestamp': last[1]
            } if last else None,
            'system_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'db_size': os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
        })
    except Exception as e:
        logger.error(f"Error en system_info: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Health check
@app.route('/health')
def health_check():
    """Endpoint de verificación de salud"""
    try:
        # Verificar base de datos
        with closing(get_db_connection()) as conn:
            conn.execute("SELECT 1")
        
        # Verificar espacio en disco
        stat = os.statvfs('/')
        disk_space = {
            'free_gb': (stat.f_bavail * stat.f_frsize) / (1024**3),
            'total_gb': (stat.f_blocks * stat.f_frsize) / (1024**3)
        }
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'disk_space': disk_space
        })
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

# Inicialización
def initialize():
    """Inicializa la aplicación"""
    ensure_indexes()
    logger.info("Aplicación inicializada")
    logger.info(f"Tamaño de la base de datos: {os.path.getsize(DB_PATH) / (1024**2):.2f} MB")

if __name__ == '__main__':
    initialize()
    
    # Usar Waitress en producción
    if os.environ.get('FLASK_ENV') == 'production':
        from waitress import serve
        serve(app, host='0.0.0.0', port=80, threads=4)
    else:
        app.run(host='0.0.0.0', port=80, debug=True)
