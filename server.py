import socket
import threading
import json
import time
from http.server import SimpleHTTPRequestHandler, HTTPServer
from datetime import datetime
import os

# Variables globales pour stocker les informations des sondes
sondes = {}  # {sonde_id: {name, ip, status, last_seen, data}}
scans = {}   # {sonde_id: [{timestamp, report_data}]}

# Classe pour gérer les états et données d'une sonde
class Sonde:
    def __init__(self, sonde_id, name, ip_address):
        self.id = sonde_id
        self.name = name
        self.ip_address = ip_address
        self.status = "disconnected"
        self.last_seen = datetime.now().isoformat()
        self.data = {}

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "ip_address": self.ip_address,
            "status": self.status,
            "last_seen": self.last_seen,
            "data": self.data
        }

    def update_status(self, status, data=None):
        self.status = status
        self.last_seen = datetime.now().isoformat()
        if data:
            self.data = data

# Fonction pour démarrer un serveur qui écoute les sondes Harvester
def start_socket_server(host='0.0.0.0', port=12345):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Socket serveur en attente de connexions sur {host}:{port}...")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connexion reçue de {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, addr))
        client_handler.daemon = True
        client_handler.start()

# Fonction pour gérer les connexions clients
def handle_client(client_socket, addr):
    try:
        data = client_socket.recv(8192).decode()
        if data:
            try:
                message = json.loads(data)
                command = message.get("command")
                
                if command == "register":
                    response = handle_register(message, addr)
                elif command == "heartbeat":
                    response = handle_heartbeat(message)
                elif command == "scan":
                    response = handle_scan(message)
                else:
                    response = {"status": "error", "message": "Commande inconnue"}
                
                client_socket.sendall(json.dumps(response).encode())
            except json.JSONDecodeError:
                client_socket.sendall(json.dumps({"status": "error", "message": "Format JSON invalide"}).encode())
    except Exception as e:
        print(f"Erreur lors du traitement de la connexion de {addr}: {str(e)}")
    finally:
        client_socket.close()

# Gestionnaire pour l'enregistrement d'une nouvelle sonde
def handle_register(message, addr):
    sonde_name = message.get("name", f"Sonde-{addr[0]}")
    sonde_id = message.get("id", str(len(sondes) + 1))
    
    # Créer ou mettre à jour la sonde
    if sonde_id not in sondes:
        sondes[sonde_id] = Sonde(sonde_id, sonde_name, addr[0])
    else:
        sondes[sonde_id].name = sonde_name
        sondes[sonde_id].ip_address = addr[0]
    
    sondes[sonde_id].update_status("connected")
    
    return {
        "status": "success", 
        "message": "Sonde enregistrée avec succès", 
        "sonde_id": sonde_id
    }

# Gestionnaire pour les heartbeats des sondes
def handle_heartbeat(message):
    sonde_id = message.get("sonde_id")
    data = message.get("data", {})
    
    if sonde_id not in sondes:
        return {"status": "error", "message": "Sonde inconnue"}
    
    sondes[sonde_id].update_status("connected", data)
    
    return {
        "status": "success", 
        "message": "Heartbeat reçu"
    }

# Gestionnaire pour les rapports de scan
def handle_scan(message):
    sonde_id = message.get("sonde_id")
    report_data = message.get("report_data")
    
    if sonde_id not in sondes:
        return {"status": "error", "message": "Sonde inconnue"}
    
    if sonde_id not in scans:
        scans[sonde_id] = []
    
    # Ajouter le rapport de scan
    scans[sonde_id].append({
        "timestamp": datetime.now().isoformat(),
        "report_data": report_data
    })
    
    return {
        "status": "success", 
        "message": "Rapport de scan enregistré"
    }

# Vérifier périodiquement l'état des sondes
def check_sondes_status():
    while True:
        now = datetime.now()
        for sonde_id, sonde in sondes.items():
            last_seen = datetime.fromisoformat(sonde.last_seen)
            # Marquer comme déconnectée si pas de heartbeat depuis 2 minutes
            if (now - last_seen).total_seconds() > 120 and sonde.status == "connected":
                sonde.status = "disconnected"
                print(f"Sonde {sonde.name} ({sonde_id}) marquée comme déconnectée")
        time.sleep(60)  # Vérifier toutes les minutes

# Thread pour exécuter le serveur de socket en parallèle
def run_socket_server():
    server_thread = threading.Thread(target=start_socket_server)
    server_thread.daemon = True
    server_thread.start()

# Thread pour vérifier le statut des sondes
def run_status_checker():
    status_thread = threading.Thread(target=check_sondes_status)
    status_thread.daemon = True
    status_thread.start()

# Gestionnaire HTTP pour servir le tableau de bord
class DashboardHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.serve_dashboard()
        elif self.path.startswith('/dashboard/'):
            sonde_id = self.path.split('/')[-1]
            self.serve_sonde_dashboard(sonde_id)
        elif self.path.startswith('/scan/'):
            sonde_id = self.path.split('/')[-1]
            self.serve_scan_report(sonde_id)
        elif self.path == '/api/sondes':
            self.serve_sondes_api()
        else:
            # Servir les fichiers statiques si existants
            super().do_GET()

    def serve_dashboard(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        # Construire la page HTML du tableau de bord principal
        html_content = '''
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Seahawks Nester - Tableau de bord</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f9;
                    margin: 0;
                    padding: 0;
                }
                .container {
                    width: 90%;
                    margin: 0 auto;
                    padding: 20px;
                }
                header {
                    background-color: #0056b3;
                    color: white;
                    padding: 10px 0;
                    text-align: center;
                }
                h1, h2 {
                    margin-top: 0;
                }
                .card {
                    background: #fff;
                    border-radius: 8px;
                    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
                    margin: 20px 0;
                    padding: 20px;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                }
                th, td {
                    padding: 12px 15px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }
                th {
                    background-color: #f8f9fa;
                }
                tr:hover {
                    background-color: #f1f1f1;
                }
                .badge {
                    padding: 5px 10px;
                    border-radius: 4px;
                    font-size: 12px;
                    font-weight: bold;
                }
                .badge-success {
                    background-color: #28a745;
                    color: white;
                }
                .badge-danger {
                    background-color: #dc3545;
                    color: white;
                }
                .btn {
                    display: inline-block;
                    padding: 6px 12px;
                    margin-bottom: 0;
                    font-size: 14px;
                    font-weight: 400;
                    text-align: center;
                    white-space: nowrap;
                    vertical-align: middle;
                    cursor: pointer;
                    border: 1px solid transparent;
                    border-radius: 4px;
                    text-decoration: none;
                }
                .btn-primary {
                    color: #fff;
                    background-color: #0056b3;
                }
                .btn-info {
                    color: #fff;
                    background-color: #17a2b8;
                }
                .refresh {
                    margin: 20px 0;
                    display: flex;
                    justify-content: flex-end;
                }
            </style>
        </head>
        <body>
            <header>
                <div class="container">
                    <h1>Seahawks Nester</h1>
                </div>
            </header>

            <div class="container">
                <div class="refresh">
                    <button onclick="window.location.reload()" class="btn btn-primary">Actualiser</button>
                </div>
                
                <div class="card">
                    <h2>Liste des sondes configurées</h2>
        '''
        
        # Ajouter les données des sondes
        if sondes:
            html_content += '''
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Nom</th>
                                <th>Adresse IP</th>
                                <th>État</th>
                                <th>Dernière connexion</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
            '''
            
            for sonde_id, sonde in sondes.items():
                status_class = "badge-success" if sonde.status == "connected" else "badge-danger"
                status_text = "Connectée" if sonde.status == "connected" else "Déconnectée"
                
                # Formater la date de dernière connexion
                try:
                    last_seen_date = datetime.fromisoformat(sonde.last_seen)
                    last_seen_format = last_seen_date.strftime("%d/%m/%Y %H:%M:%S")
                except:
                    last_seen_format = sonde.last_seen
                
                html_content += f'''
                            <tr>
                                <td>{sonde.id}</td>
                                <td>{sonde.name}</td>
                                <td>{sonde.ip_address}</td>
                                <td><span class="badge {status_class}">{status_text}</span></td>
                                <td>{last_seen_format}</td>
                                <td>
                                    <a href="/dashboard/{sonde.id}" class="btn btn-primary">Tableau de bord</a>
                                    <a href="/scan/{sonde.id}" class="btn btn-info">Dernier scan</a>
                                </td>
                            </tr>
                '''
            
            html_content += '''
                        </tbody>
                    </table>
            '''
        else:
            html_content += "<p>Aucune sonde n'est enregistrée pour le moment.</p>"
        
        html_content += '''
                </div>
            </div>
        </body>
        </html>
        '''
        
        self.wfile.write(html_content.encode('utf-8'))

    def serve_sonde_dashboard(self, sonde_id):
        if sonde_id not in sondes:
            self.send_error(404, "Sonde non trouvée")
            return
        
        sonde = sondes[sonde_id]
        
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        
        # Construire la page HTML du tableau de bord de la sonde
        html_content = f'''
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Tableau de bord - {sonde.name}</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f9;
                    margin: 0;
                    padding: 0;
                }}
                .container {{
                    width: 90%;
                    margin: 0 auto;
                    padding: 20px;
                }}
                header {{
                    background-color: #0056b3;
                    color: white;
                    padding: 10px 0;
                    text-align: center;
                }}
                h1, h2 {{
                    margin-top: 0;
                }}
                .card {{
                    background: #fff;
                    border-radius: 8px;
                    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
                    margin: 20px 0;
                    padding: 20px;
                }}
                .badge {{
                    padding: 5px 10px;
                    border-radius: 4px;
                    font-size: 12px;
                    font-weight: bold;
                }}
                .badge-success {{
                    background-color: #28a745;
                    color: white;
                }}
                .badge-danger {{
                    background-color: #dc3545;
                    color: white;
                }}
                .btn {{
                    display: inline-block;
                    padding: 6px 12px;
                    margin-bottom: 0;
                    font-size: 14px;
                    font-weight: 400;
                    text-align: center;
                    white-space: nowrap;
                    vertical-align: middle;
                    cursor: pointer;
                    border: 1px solid transparent;
                    border-radius: 4px;
                    text-decoration: none;
                }}
                .btn-primary {{
                    color: #fff;
                    background-color: #0056b3;
                }}
                .btn-secondary {{
                    color: #fff;
                    background-color: #6c757d;
                }}
                .grid {{
                    display: grid;
                    grid-template-columns: 1fr 2fr;
                    gap: 20px;
                }}
                .data-item {{
                    margin-bottom: 15px;
                    padding-bottom: 15px;
                    border-bottom: 1px solid #eee;
                }}
                .data-title {{
                    font-weight: bold;
                    margin-bottom: 5px;
                }}
                .actions {{
                    margin: 20px 0;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }}
                pre {{
                    background-color: #f8f9fa;
                    padding: 10px;
                    border-radius: 4px;
                    overflow: auto;
                }}
            </style>
        </head>
        <body>
            <header>
                <div class="container">
                    <h1>Tableau de bord : {sonde.name}</h1>
                </div>
            </header>

            <div class="container">
                <div class="actions">
                    <a href="/" class="btn btn-secondary">Retour à la liste</a>
                    <button onclick="window.location.reload()" class="btn btn-primary">Actualiser</button>
                </div>
                
                <div class="grid">
                    <div class="card">
                        <h2>Informations de la sonde</h2>
                        <div class="data-item">
                            <div class="data-title">ID:</div>
                            <div>{sonde.id}</div>
                        </div>
                        <div class="data-item">
                            <div class="data-title">Nom:</div>
                            <div>{sonde.name}</div>
                        </div>
                        <div class="data-item">
                            <div class="data-title">Adresse IP:</div>
                            <div>{sonde.ip_address}</div>
                        </div>
                        <div class="data-item">
                            <div class="data-title">État:</div>
                            <div>
                            '''
        
        status_class = "badge-success" if sonde.status == "connected" else "badge-danger"
        status_text = "Connectée" if sonde.status == "connected" else "Déconnectée"
        html_content += f'<span class="badge {status_class}">{status_text}</span>'
        
        # Formater la date de dernière connexion
        try:
            last_seen_date = datetime.fromisoformat(sonde.last_seen)
            last_seen_format = last_seen_date.strftime("%d/%m/%Y %H:%M:%S")
        except:
            last_seen_format = sonde.last_seen
        
        html_content += f'''
                            </div>
                        </div>
                        <div class="data-item">
                            <div class="data-title">Dernière connexion:</div>
                            <div>{last_seen_format}</div>
                        </div>
                        
                        <a href="/scan/{sonde.id}" class="btn btn-primary">Voir le dernier rapport de scan</a>
                    </div>
                    
                    <div class="card">
                        <h2>Données de surveillance</h2>
        '''
        
        if sonde.data:
            for key, value in sonde.data.items():
                html_content += f'''
                        <div class="data-item">
                            <div class="data-title">{key}:</div>
                            <div>
                '''
                
                if isinstance(value, dict) or isinstance(value, list):
                    html_content += f'<pre>{json.dumps(value, indent=2)}</pre>'
                else:
                    html_content += f'{value}'
                
                html_content += '''
                            </div>
                        </div>
                '''
        else:
            html_content += "<p>Aucune donnée disponible pour cette sonde.</p>"
        
        html_content += '''
                    </div>
                </div>
            </div>
        </body>
        </html>
        '''
        
        self.wfile.write(html_content.encode('utf-8'))

    def serve_scan_report(self, sonde_id):
        if sonde_id not in sondes:
            self.send_error(404, "Sonde non trouvée")
            return
        
        sonde = sondes[sonde_id]
        
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        
        # Construire la page HTML du rapport de scan
        html_content = f'''
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Rapport de scan - {sonde.name}</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f9;
                    margin: 0;
                    padding: 0;
                }}
                .container {{
                    width: 90%;
                    margin: 0 auto;
                    padding: 20px;
                }}
                header {{
                    background-color: #0056b3;
                    color: white;
                    padding: 10px 0;
                    text-align: center;
                }}
                h1, h2 {{
                    margin-top: 0;
                }}
                .card {{
                    background: #fff;
                    border-radius: 8px;
                    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
                    margin: 20px 0;
                    padding: 20px;
                }}
                .btn {{
                    display: inline-block;
                    padding: 6px 12px;
                    margin-bottom: 0;
                    font-size: 14px;
                    font-weight: 400;
                    text-align: center;
                    white-space: nowrap;
                    vertical-align: middle;
                    cursor: pointer;
                    border: 1px solid transparent;
                    border-radius: 4px;
                    text-decoration: none;
                }}
                .btn-primary {{
                    color: #fff;
                    background-color: #0056b3;
                }}
                .btn-secondary {{
                    color: #fff;
                    background-color: #6c757d;
                }}
                .actions {{
                    margin: 20px 0;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }}
                pre {{
                    background-color: #f8f9fa;
                    padding: 15px;
                    border-radius: 4px;
                    white-space: pre-wrap;
                    word-wrap: break-word;
                    overflow: auto;
                    max-height: 500px;
                }}
                .no-data {{
                    padding: 20px;
                    text-align: center;
                    color: #6c757d;
                }}
                iframe {{
                    width: 100%;
                    height: 600px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                }}
            </style>
        </head>
        <body>
            <header>
                <div class="container">
                    <h1>Rapport de scan : {sonde.name}</h1>
                </div>
            </header>

            <div class="container">
                <div class="actions">
                    <div>
                        <a href="/" class="btn btn-secondary">Retour à la liste</a>
                        <a href="/dashboard/{sonde.id}" class="btn btn-primary">Tableau de bord</a>
                    </div>
                    <button onclick="window.location.reload()" class="btn btn-primary">Actualiser</button>
                </div>
                
                <div class="card">
        '''
        
        if sonde_id in scans and scans[sonde_id]:
            latest_scan = scans[sonde_id][-1]
            
            # Formater la date du scan
            try:
                scan_date = datetime.fromisoformat(latest_scan["timestamp"])
                scan_date_format = scan_date.strftime("%d/%m/%Y à %H:%M:%S")
            except:
                scan_date_format = latest_scan["timestamp"]
            
            html_content += f'<h2>Scan réalisé le {scan_date_format}</h2>'
            
            report_data = latest_scan["report_data"]
            if isinstance(report_data, str) and (report_data.startswith('<!DOCTYPE html>') or report_data.startswith('<html>')):
                html_content += f'<iframe srcdoc="{report_data.replace(chr(34), "&quot;")}" sandbox="allow-scripts"></iframe>'
            else:
                if isinstance(report_data, (dict, list)):
                    report_text = json.dumps(report_data, indent=2)
                else:
                    report_text = str(report_data)
                html_content += f'<pre>{report_text}</pre>'
        else:
            html_content += '<div class="no-data">Aucun rapport de scan disponible pour cette sonde.</div>'
        
        html_content += '''
                </div>
            </div>
        </body>
        </html>
        '''
        
        self.wfile.write(html_content.encode('utf-8'))

    def serve_sondes_api(self):
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        
        sondes_list = [sonde.to_dict() for sonde in sondes.values()]
        self.wfile.write(json.dumps(sondes_list).encode('utf-8'))

# Fonction pour démarrer le serveur HTTP
def start_http_server(host='0.0.0.0', port=8080):
    server_address = (host, port)
    httpd = HTTPServer(server_address, DashboardHandler)
    print(f"Serveur HTTP démarré sur {host}:{port}...")
    httpd.serve_forever()

if __name__ == '__main__':
    # Lancer le serveur socket dans un thread parallèle
    run_socket_server()
    
    # Lancer le vérificateur de statut des sondes
    run_status_checker()

    # Démarrer le serveur HTTP pour afficher le tableau de bord
    start_http_server()