from flask import Flask, request, jsonify
import mysql.connector
from mysql.connector import Error
from datetime import datetime

app = Flask(__name__)

# Configuration de la base de données
DB_CONFIG = {
    'host': '88.198.97.253',  # Modifier selon votre configuration
    'user': 'admin',  # Modifier avec votre utilisateur MySQL
    'password': 'root',  # Modifier avec votre mot de passe MySQL
    'database': 'nmap_results_db'  # Modifier avec le nom de votre base
}

# Fonction pour établir une connexion à la base de données
def get_db_connection():
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        return connection
    except Error as e:
        print(f"Erreur de connexion à la base de données: {e}")
        return None

# Route pour ajouter une sonde
@app.route('/', methods=['POST'])
def add_probe():
    action = request.args.get('action')
    if action == 'add':
        name = request.form.get('name')
        ip = request.form.get('ip')
        status = request.form.get('status', 'active')  # Par défaut "active"

        if not name or not ip:
            return jsonify({'success': False, 'message': 'Nom et IP requis'}), 400

        try:
            connection = get_db_connection()
            if connection is None:
                return jsonify({'success': False, 'message': 'Erreur de connexion à la base de données'}), 500

            cursor = connection.cursor()
            query = """INSERT INTO sondes (name, ip, status, last_seen) VALUES (%s, %s, %s, %s)"""
            cursor.execute(query, (name, ip, status, datetime.now()))
            connection.commit()

            probe_id = cursor.lastrowid
            cursor.close()
            connection.close()

            return jsonify({'success': True, 'id': probe_id}), 200

        except Error as e:
            print(f"Erreur lors de l'insertion dans la base de données: {e}")
            return jsonify({'success': False, 'message': 'Erreur lors de l\'ajout de la sonde'}), 500
    
    return jsonify({'success': False, 'message': 'Action invalide'}), 400

# Route pour récupérer les sondes enregistrées
@app.route('/', methods=['GET'])
def get_probes():
    action = request.args.get('action')
    if action == 'get':
        try:
            connection = get_db_connection()
            if connection is None:
                return jsonify({'success': False, 'message': 'Erreur de connexion à la base de données'}), 500

            cursor = connection.cursor(dictionary=True)
            cursor.execute("SELECT * FROM sondes")
            sondes = cursor.fetchall()
            connection.close()

            return jsonify({'success': True, 'data': sondes}), 200 if sondes else (jsonify({'success': False, 'message': 'Aucune sonde trouvée'}), 404)
        
        except Error as e:
            print(f"Erreur lors de la récupération des sondes: {e}")
            return jsonify({'success': False, 'message': 'Erreur lors de la récupération des sondes'}), 500
    
    return jsonify({'message': 'Bienvenue sur l\'API probes'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
