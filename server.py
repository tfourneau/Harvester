from flask import Flask, request, jsonify
import mysql.connector
from mysql.connector import Error
from datetime import datetime

app = Flask(__name__)

DB_CONFIG = {
    'host': '88.198.97.253',
    'user': 'admin',
    'password': 'root',
    'database': 'nmap_results_db'
}

def get_db_connection():
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except Error as e:
        print(f"[DB ERROR] {e}")
        return None

@app.route('/', methods=['POST'])
def manage_probe():
    action = request.args.get('action')

    if action == 'add':
        name = request.form.get('name')
        ip = request.form.get('ip')
        status = request.form.get('status', 'active')

        if not name or not ip:
            return jsonify({'success': False, 'message': 'Nom et IP requis'}), 400

        try:
            conn = get_db_connection()
            if conn is None:
                return jsonify({'success': False, 'message': 'Erreur de connexion BDD'}), 500

            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO sondes (name, ip, status, last_seen) VALUES (%s, %s, %s, %s)",
                (name, ip, status, datetime.now())
            )
            conn.commit()
            probe_id = cursor.lastrowid
            cursor.close()
            conn.close()

            return jsonify({'success': True, 'id': probe_id}), 200

        except Error as e:
            print(f"[INSERT ERROR] {e}")
            return jsonify({'success': False, 'message': 'Erreur lors de l\'ajout'}), 500

    elif action == 'update':
        probe_id = request.form.get('id')
        name = request.form.get('name')
        ip = request.form.get('ip')
        status = request.form.get('status')

        if not probe_id or not name or not ip:
            return jsonify({'success': False, 'message': 'ID, nom et IP requis'}), 400

        try:
            conn = get_db_connection()
            if conn is None:
                return jsonify({'success': False, 'message': 'Erreur de connexion BDD'}), 500

            cursor = conn.cursor()
            cursor.execute(
                "UPDATE sondes SET name=%s, ip=%s, status=%s, last_seen=%s WHERE id=%s",
                (name, ip, status, datetime.now(), probe_id)
            )
            conn.commit()
            cursor.close()
            conn.close()

            return jsonify({'success': True, 'message': 'Sonde mise à jour'}), 200

        except Error as e:
            print(f"[UPDATE ERROR] {e}")
            return jsonify({'success': False, 'message': 'Erreur mise à jour'}), 500

    elif action == 'ping':
        probe_id = request.form.get('id')
        if not probe_id:
            return jsonify({'success': False, 'message': 'ID manquant'}), 400

        try:
            conn = get_db_connection()
            if conn is None:
                return jsonify({'success': False, 'message': 'Erreur de connexion BDD'}), 500

            cursor = conn.cursor()
            cursor.execute(
                "UPDATE sondes SET last_seen=%s WHERE id=%s",
                (datetime.now(), probe_id)
            )
            conn.commit()
            cursor.close()
            conn.close()

            return jsonify({'success': True, 'reachable': True}), 200

        except Error as e:
            print(f"[PING ERROR] {e}")
            return jsonify({'success': False, 'message': 'Erreur ping'}), 500

    return jsonify({'success': False, 'message': 'Action invalide'}), 400

@app.route('/', methods=['GET'])
def get_probe():
    action = request.args.get('action')
    if action == 'get':
        probe_id = request.args.get('id')

        try:
            conn = get_db_connection()
            if conn is None:
                return jsonify({'success': False, 'message': 'Erreur de connexion BDD'}), 500

            cursor = conn.cursor(dictionary=True)

            if probe_id:
                cursor.execute("SELECT * FROM sondes WHERE id = %s", (probe_id,))
                probe = cursor.fetchone()
                cursor.close()
                conn.close()
                if probe:
                    return jsonify({'success': True, 'probe': probe}), 200
                else:
                    return jsonify({'success': False, 'message': 'Sonde introuvable'}), 404
            else:
                cursor.execute("SELECT * FROM sondes")
                sondes = cursor.fetchall()
                cursor.close()
                conn.close()
                return jsonify({'success': True, 'data': sondes}), 200

        except Error as e:
            print(f"[GET ERROR] {e}")
            return jsonify({'success': False, 'message': 'Erreur récupération'}), 500

    return jsonify({'message': 'Bienvenue sur l\'API probes'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
