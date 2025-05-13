from flask import Flask, render_template, request, jsonify
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
    """Página principal con los últimos registros"""
    try:
        with closing(get_db_connection()) as conn:
            limit = min(int(request.args.get('limit', 10)), 1000)
            date_filter = request.args.get('date')
            cursor = conn.cursor()
            query = """
                       SELECT value, timestamp 
                       FROM sensor_data
                       {date_filter}
                       ORDER BY timestamp DESC 
                       LIMIT ?
                    """
            params = []

            whereclause = ""
            if date_filter:
                whereclause = "WHERE DATE(timestamp) = ?"
                params.append(date_filter)

            params.append(limit)

            cursor.execute(query.format(date_filter=whereclause), params)
            fetched = cursor.fetchall()
            data = []
            for row in fetched:
                if len(row) >= 2:
                   (value, timestamp) = row
                   data.append({'value': value, 'timestamp': timestamp})

        return render_template('index.html', 
                            data=data, 
                            current_year=datetime.now().year)
    except Exception as e:
        logger.error(f"Error en index: {str(e)}")
        return render_template('error.html', message="Error al cargar datos"), 500

# API de datos
@app.route('/api/sensor/data', methods=['GET'])
def get_sensor_data():
    """API para obtener datos del sensor con paginación"""
    try:
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, int(request.args.get('limit', 10)))
        date_filter = request.args.get('date')

        with closing(get_db_connection()) as conn:
            cursor = conn.cursor()
            
            # Consulta de conteo
            count_query = "SELECT COUNT(*) FROM sensor_data"
            count_params = []
            
            if date_filter:
                count_query += " WHERE DATE(timestamp) = ?"
                count_params.append(date_filter)
            
            cursor.execute(count_query, count_params)
            total = cursor.fetchone()[0]
            
            # Consulta de datos
            data_query = """
                SELECT value, timestamp 
                FROM sensor_data
                {date_filter}
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            """
            
            params = []
            where_clause = ""
            
            if date_filter:
                where_clause = "WHERE DATE(timestamp) = ?"
                params.append(date_filter)
            
            params.extend([per_page, (page - 1) * per_page])
            
            cursor.execute(data_query.format(date_filter=where_clause), params)
            data = [{'value': row[0], 'timestamp': row[1]} for row in cursor]
            
            return jsonify({
                'data': data,
                'pagination': {
                    'total': total,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': (total + per_page - 1) // per_page
                }
            })
    except Exception as e:
        logger.error(f"Error en get_sensor_data: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Estadísticas y resúmenes
@lru_cache(maxsize=32)
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

@app.route('/api/sensor/daily_stats', methods=['GET'])
def get_daily_stats():
    """API para obtener estadísticas diarias"""
    try:
        month = int(request.args.get('month', datetime.now().month))
        year = int(request.args.get('year', datetime.now().year))
        stats = get_cached_daily_stats(month, year)
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error en get_daily_stats: {str(e)}")
        return jsonify({'error': str(e)}), 500

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

# Panel de administración
@app.route('/admin', methods=['GET', 'POST'])
def admin_panel():
    """Panel de administración del sistema"""
    try:
        with closing(get_db_connection()) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM sensor_data")
            count = cursor.fetchone()[0]
            
            cursor.execute("SELECT value, timestamp FROM sensor_data ORDER BY timestamp DESC LIMIT 1")
            last_record = cursor.fetchone()
        
        if request.method == 'POST':
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
                    # Limpiar caché de estadísticas
                    get_cached_daily_stats.cache_clear()
                except Exception as e:
                    message = f"Error al borrar datos: {str(e)}"
            
            elif action == 'update_system':
                try:
                    update_script = '/home/rud1/scripts/update_system.sh'
                    
                    if not os.path.exists(update_script):
                        message = "Error: Script de actualización no encontrado"
                    else:
                        # Ejecutar en segundo plano y desconectar completamente
                        
                        def run_update():
                            # Usamos nohup y redirección para desconectar completamente
                            subprocess.Popen([
                                'sudo', 'nohup', update_script,
                                '>/tmp/update.log', '2>/tmp/update_error.log', '&'
                            ], preexec_fn=os.setpgrp)
                        
                        # Lanzar en un hilo para no bloquear la respuesta
                        Thread(target=run_update).start()
                        
                        message = "Actualización iniciada. El sistema se reiniciará cuando termine."
                        
                except Exception as e:
                    message = f"Error al iniciar actualización: {str(e)}"
            
            return render_template('admin.html', 
                                message=message,
                                count=count,
                                last_record=last_record)
        
        return render_template('admin.html',
                            count=count,
                            last_record=last_record)
    except Exception as e:
        logger.error(f"Error en admin_panel: {str(e)}")
        return render_template('error.html', message="Error en el panel de administración"), 500

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
