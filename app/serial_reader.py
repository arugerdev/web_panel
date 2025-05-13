#!/usr/bin/env python3
import serial
import serial.tools.list_ports
import sqlite3
from datetime import datetime
import time
import logging

# Configuración
DB_PATH = '/home/rud1/web_panel/data/sensor_data.db'
BAUDRATE = 9600
TIMEOUT = 1
CHECK_PORTS_INTERVAL = 5  # Segundos entre chequeos de puertos

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/rud1/web_panel/logs/serial_reader.log'),
        logging.StreamHandler()
    ]
)

def init_db():
    """Inicializa la base de datos"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS sensor_data
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      value REAL,
                      timestamp DATETIME)''')
        conn.commit()
        conn.close()
        logging.info("Base de datos inicializada correctamente")
    except Exception as e:
        logging.error(f"Error al inicializar la base de datos: {e}")

def get_serial_ports():
    """Obtiene la lista de puertos seriales USB disponibles"""
    ports = []
    try:
        available_ports = serial.tools.list_ports.comports()
        for port in available_ports:
            if 'USB' in port.description or 'ACM' in port.device:
                ports.append(port.device)
        logging.debug(f"Puertos encontrados: {ports}")
    except Exception as e:
        logging.error(f"Error al buscar puertos: {e}")
    return ports

def read_from_port(port_name):
    """Intenta leer datos de un puerto serial específico"""
    try:
        with serial.Serial(port_name, BAUDRATE, timeout=TIMEOUT) as ser:
            ser.flush()
            logging.info(f"Leyendo del puerto {port_name}")
            
            while True:
                if ser.in_waiting > 0:
                    line = ser.readline().decode('utf-8').rstrip()
                    try:
                        value = float(line)
                        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        
                        conn = sqlite3.connect(DB_PATH)
                        c = conn.cursor()
                        c.execute("INSERT INTO sensor_data (value, timestamp) VALUES (?, ?)",
                                 (value, timestamp))
                        conn.commit()
                        conn.close()
                        
                        logging.info(f"Saved: {value} at {timestamp} from {port_name}")
                    except ValueError:
                        logging.warning(f"Dato inválido desde {port_name}: {line}")
                    except sqlite3.Error as e:
                        logging.error(f"Error de base de datos: {e}")
                
                time.sleep(0.1)
                
    except serial.SerialException as e:
        logging.warning(f"Error con el puerto {port_name}: {e}")
    except Exception as e:
        logging.error(f"Error inesperado con {port_name}: {e}")

def main():
    """Función principal"""
    init_db()
    active_port = None
    
    while True:
        # Buscar puertos disponibles
        available_ports = get_serial_ports()
        
        if not available_ports:
            logging.warning("No se encontraron puertos USB disponibles")
            time.sleep(CHECK_PORTS_INTERVAL)
            continue
            
        # Si el puerto activo ya no está disponible
        if active_port and active_port not in available_ports:
            logging.warning(f"Puerto {active_port} desconectado")
            active_port = None
            
        # Si no hay puerto activo, intentar conectar a uno nuevo
        if not active_port:
            for port in available_ports:
                try:
                    # Probar si el puerto es legible
                    test_ser = serial.Serial(port, BAUDRATE, timeout=TIMEOUT)
                    test_ser.close()
                    active_port = port
                    logging.info(f"Conectado a nuevo puerto: {port}")
                    break
                except serial.SerialException:
                    continue
                    
        # Si encontramos un puerto válido, leer de él
        if active_port:
            read_from_port(active_port)
        else:
            logging.warning("No se pudo conectar a ningún puerto válido")
            time.sleep(CHECK_PORTS_INTERVAL)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Script detenido manualmente")
    except Exception as e:
        logging.critical(f"Error crítico: {e}")
