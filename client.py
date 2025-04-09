import subprocess
import socket
import time
import nmap
import mysql.connector
import git
import psutil
import shutil
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import threading
import logging
import os
import json
import requests
from datetime import datetime

# Configuration du logging
logging.basicConfig(
    filename='harvester.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class HarvesterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Tableau de Bord Harvester")
        self.root.geometry("800x600")
        self.root.minsize(600, 400)
        
        # Variables
        self.selected_ip = tk.StringVar()
        self.selected_netmask = tk.StringVar()
        self.dashboard_info = tk.StringVar()
        self.interfaces = []
        self.scan_results = {}
        self.scan_running = False
        
        # Configuration serveur
        self.server_url = "http://88.198.97.251:5000"
        self.db_config = {
            'host': '88.198.97.253',
            'user': 'admin',
            'password': 'root',
            'database': 'nmap_results_db',
            'port': 3306
        }
        
        # Menu principal
        self.create_menu()
        
        # Création de l'interface
        self.create_interface()
        
        # Récupération des interfaces réseau au démarrage
        self.load_network_interfaces()
        
        # Enregistrement de la sonde au démarrage
        self.initialize_probe()
        # Configuration des styles
        self.configure_styles()
        
        # Lancement de l'envoi périodique du statut
        self.start_status_updater()

    def configure_styles(self):
        style = ttk.Style()
        style.configure("TButton", padding=6, relief="flat", background="#3498db")
        style.configure("Scan.TButton", padding=6, background="#27ae60")
        style.configure("Update.TButton", padding=6, background="#e74c3c")

    def create_menu(self):
        menu_bar = tk.Menu(self.root)
        
        # Menu Fichier
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Exporter les résultats", command=self.export_results)
        file_menu.add_separator()
        file_menu.add_command(label="Quitter", command=self.root.quit)
        menu_bar.add_cascade(label="Fichier", menu=file_menu)
        
        # Menu Outils
        tools_menu = tk.Menu(menu_bar, tearoff=0)
        tools_menu.add_command(label="Configuration BDD", command=self.show_db_config)
        tools_menu.add_command(label="Configuration Serveur", command=self.show_server_config)
        tools_menu.add_command(label="Rafraîchir interfaces", command=self.load_network_interfaces)
        menu_bar.add_cascade(label="Outils", menu=tools_menu)
        
        # Menu Sondes
        probes_menu = tk.Menu(menu_bar, tearoff=0)
        probes_menu.add_command(label="Enregistrer la sonde", command=self.register_probe)
        probes_menu.add_command(label="Tester connexion serveur", command=self.test_server_connection)
        probes_menu.add_command(label="Envoyer état actuel", command=self.send_probe_status)
        menu_bar.add_cascade(label="Sondes", menu=probes_menu)
        
        # Menu Aide
        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="À propos", command=self.show_about)
        menu_bar.add_cascade(label="Aide", menu=help_menu)
        
        self.root.config(menu=menu_bar)

    def create_interface(self):
        # Frame principale avec deux colonnes
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Colonne gauche (contrôles)
        control_frame = ttk.LabelFrame(main_frame, text="Configuration", padding="10")
        control_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))
        
        # Sélection de l'interface
        ttk.Label(control_frame, text="Interface réseau:").pack(anchor=tk.W, pady=(0, 5))
        self.ip_menu = ttk.Combobox(control_frame, textvariable=self.selected_ip, width=25)
        self.ip_menu.pack(anchor=tk.W, pady=(0, 10), fill=tk.X)
        self.ip_menu.bind("<<ComboboxSelected>>", self.update_selected_netmask)
        
        # Informations sur la sonde
        probe_frame = ttk.LabelFrame(control_frame, text="Informations de la sonde")
        probe_frame.pack(fill=tk.X, pady=10)
        
        self.probe_id_var = tk.StringVar(value="Non enregistré")
        self.probe_status_var = tk.StringVar(value="Inconnu")
        
        ttk.Label(probe_frame, text="ID de la sonde:").pack(anchor=tk.W, pady=(5, 0))
        ttk.Label(probe_frame, textvariable=self.probe_id_var, font=("", 9, "bold")).pack(anchor=tk.W, pady=(0, 5))
        
        ttk.Label(probe_frame, text="Statut:").pack(anchor=tk.W, pady=(5, 0))
        ttk.Label(probe_frame, textvariable=self.probe_status_var, font=("", 9, "bold")).pack(anchor=tk.W, pady=(0, 5))
        
        # Options de scan
        ttk.Label(control_frame, text="Options de scan:").pack(anchor=tk.W, pady=(10, 5))
        
        # Frame pour les options
        options_frame = ttk.Frame(control_frame)
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.scan_type = tk.StringVar(value="normal")
        ttk.Radiobutton(options_frame, text="Normal", variable=self.scan_type, value="normal").pack(anchor=tk.W)
        ttk.Radiobutton(options_frame, text="Rapide", variable=self.scan_type, value="fast").pack(anchor=tk.W)
        ttk.Radiobutton(options_frame, text="Complet", variable=self.scan_type, value="full").pack(anchor=tk.W)
        
        # Boutons d'action
        btn_frame = ttk.Frame(control_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        self.scan_button = ttk.Button(btn_frame, text="Lancer le scan", command=self.start_scan, style="Scan.TButton")
        self.scan_button.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Button(btn_frame, text="Mettre à jour l'application", command=self.update_application, style="Update.TButton").pack(fill=tk.X)
        
        # Indicateur de statut
        self.status_var = tk.StringVar(value="Prêt")
        ttk.Label(control_frame, textvariable=self.status_var).pack(anchor=tk.W, pady=10)
        
        # Indicateur de progression
        self.progress = ttk.Progressbar(control_frame, orient=tk.HORIZONTAL, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=(0, 10))
        
        # Colonne droite (résultats)
        results_frame = ttk.LabelFrame(main_frame, text="Résultats du scan", padding="10")
        results_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Zone de texte défilante pour les résultats
        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, height=20)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        self.results_text.config(state=tk.DISABLED)

    def load_network_interfaces(self):
        self.interfaces = self.get_network_interfaces()
        self.ip_menu['values'] = [f"{iface[1]} ({iface[0]}) - {iface[2]}" for iface in self.interfaces]
        if self.interfaces:
            self.ip_menu.current(0)
            self.update_selected_netmask(None)
        else:
            messagebox.showwarning("Attention", "Aucune interface réseau IPv4 n'a été détectée.")

    def update_selected_netmask(self, event):
        if not self.interfaces:
            return
            
        selected_index = self.ip_menu.current()
        if selected_index >= 0 and selected_index < len(self.interfaces):
            self.selected_netmask.set(self.interfaces[selected_index][2])

    def get_network_interfaces(self):
        interfaces = []
        try:
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:  # Adresses IPv4 uniquement
                        netmask = None
                        for addr_info in addrs:
                            if addr_info.family == socket.AF_INET and addr_info.netmask:
                                netmask = addr_info.netmask
                        
                        # Vérification et correction du masque
                        if not netmask or netmask == '':
                            logging.warning(f"Masque de sous-réseau vide pour l'interface {interface}. Attribution du masque par défaut.")
                            netmask = '255.255.255.0'
                            
                        interfaces.append((interface, addr.address, netmask))
        except Exception as e:
            logging.error(f"Erreur lors de la récupération des interfaces: {e}")
            messagebox.showerror("Erreur", f"Impossible de récupérer les interfaces réseau: {e}")
            
        return interfaces

    def calculate_network(self, ip, netmask):
        try:
            # Gestion des masques au format CIDR ou décimal
            if netmask.startswith('/'):
                cidr = netmask
            elif netmask.count('.') == 3:
                # Conversion du masque décimal en CIDR
                cidr = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
                cidr = f"/{cidr}"
            else:
                raise ValueError(f"Format de masque non reconnu: {netmask}")
                
            # Cas spécial pour /32 (un seul hôte)
            if netmask == '255.255.255.255' or netmask == '/32':
                return ip
                
            network = ipaddress.IPv4Network(f"{ip}{cidr}", strict=False)
            return str(network)
        except Exception as e:
            logging.error(f"Erreur lors du calcul du réseau: {e}")
            return None

    def start_scan(self):
        if self.scan_running:
            messagebox.showinfo("Information", "Un scan est déjà en cours. Veuillez patienter.")
            return
            
        # Récupération des valeurs sélectionnées
        selected_interface = self.ip_menu.get()
        if not selected_interface:
            messagebox.showwarning("Attention", "Veuillez sélectionner une interface réseau.")
            return
            
        # Extraction de l'IP depuis la chaîne sélectionnée
        ip_parts = selected_interface.split()
        if not ip_parts:
            messagebox.showwarning("Attention", "Format d'interface invalide.")
            return
            
        ip_address = ip_parts[0]
        
        # Lancement du scan dans un thread séparé
        self.scan_running = True
        self.scan_button.config(state=tk.DISABLED)
        self.status_var.set("Scan en cours...")
        self.progress.start()
        
        scan_thread = threading.Thread(
            target=self.run_network_scan,
            args=(ip_address, self.selected_netmask.get(), self.scan_type.get())
        )
        scan_thread.daemon = True
        scan_thread.start()

    def run_network_scan(self, ip, netmask, scan_type):
        try:
            # Mise à jour de l'interface
            self.update_text_widget("Démarrage du scan réseau...\n")
            self.update_text_widget(f"Adresse IP: {ip}\n")
            self.update_text_widget(f"Masque de sous-réseau: {netmask}\n")
            self.update_text_widget(f"Type de scan: {scan_type}\n\n")
            
            # Calcul du réseau cible
            network = self.calculate_network(ip, netmask)
            if not network:
                self.update_text_widget("Erreur: Impossible de calculer l'adresse réseau.\n")
                return
                
            self.update_text_widget(f"Scan du réseau: {network}\n\n")
            
            # Configuration des arguments nmap selon le type de scan
            if scan_type == "fast":
                ping_args = "-sP -T5"  # Ping sweep très rapide
                port_args = "-F -T5"   # Scan rapide des ports les plus courants
            elif scan_type == "full":
                ping_args = "-sP -T4"  # Ping sweep normal
                port_args = "-p 1-65535 -T4"  # Scan complet de tous les ports
            else:  # normal
                ping_args = "-sP -T4"  # Ping sweep normal
                port_args = "-p 1-1000 -T4"  # Scan des 1000 premiers ports
            
            # Création du scanner
            nm = nmap.PortScanner()
            
            # Découverte des hôtes actifs
            self.update_text_widget("Découverte des hôtes...\n")
            nm.scan(hosts=network, arguments=ping_args)
            
            # Résultats du scan
            scan_results = {}
            total_hosts = len(nm.all_hosts())
            self.update_text_widget(f"Hôtes découverts: {total_hosts}\n\n")
            
            # Scanner les ports pour chaque hôte
            for i, host in enumerate(nm.all_hosts()):
                self.update_text_widget(f"Scan de l'hôte {i+1}/{total_hosts}: {host}\n")
                
                # Création de la structure pour les données de l'hôte
                host_data = {
                    'ip': host,
                    'hostname': nm[host].hostname() if 'hostname' in nm[host] else "",
                    'ports': []
                }
                
                # Scan des ports pour cet hôte
                try:
                    nm.scan(hosts=host, arguments=port_args)
                    for proto in nm[host].all_protocols():
                        lport = sorted(nm[host][proto].keys())
                        for port in lport:
                            service = nm[host][proto][port]['name']
                            state = nm[host][proto][port]['state']
                            port_info = {
                                'port': port,
                                'protocol': proto,
                                'service': service,
                                'state': state
                            }
                            host_data['ports'].append(port_info)
                            
                            # Affichage en temps réel
                            self.update_text_widget(f"  - Port {port}/{proto}: {service} ({state})\n")
                except Exception as e:
                    self.update_text_widget(f"  - Erreur lors du scan des ports: {e}\n")
                
                scan_results[host] = host_data
                self.update_text_widget(f"  Terminé: {len(host_data['ports'])} ports trouvés\n\n")
            
            # Enregistrement des résultats
            self.scan_results = scan_results
            
            # Tentative d'enregistrement en base de données
            try:
                self.update_text_widget("Enregistrement des résultats en base de données...\n")
                self.store_scan_results(scan_results)
                self.update_text_widget("Enregistrement terminé.\n")
            except Exception as e:
                self.update_text_widget(f"Erreur lors de l'enregistrement en base de données: {e}\n")
            
            # Mise à jour du statut de la sonde après un scan réussi
            try:
                self.send_probe_status()
                self.update_text_widget("Statut de la sonde mis à jour.\n")
            except Exception as e:
                self.update_text_widget(f"Erreur lors de la mise à jour du statut: {e}\n")
            
            # Fin du scan
            self.update_text_widget("\nScan terminé avec succès!\n")
            self.update_text_widget(f"Nombre total d'hôtes: {total_hosts}\n")
            self.update_text_widget(f"Nombre total de ports ouverts: {sum(len(data['ports']) for data in scan_results.values())}\n")
            
        except Exception as e:
            self.update_text_widget(f"Erreur lors du scan: {e}\n")
            logging.error(f"Erreur lors du scan: {e}")
        finally:
            # Réinitialisation de l'interface
            self.root.after(0, self.finish_scan)

    def finish_scan(self):
        self.scan_running = False
        self.scan_button.config(state=tk.NORMAL)
        self.status_var.set("Prêt")
        self.progress.stop()

    def update_text_widget(self, text):
        # Cette fonction met à jour le widget de texte depuis n'importe quel thread
        self.root.after(0, self._update_text, text)

    def _update_text(self, text):
        self.results_text.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, text)
        self.results_text.see(tk.END)
        self.results_text.config(state=tk.DISABLED)

    def store_scan_results(self, scan_results):
        try:
            conn = mysql.connector.connect(**self.db_config)
            cursor = conn.cursor()
            
            # Création de la table si elle n'existe pas
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS nmap_results (
                id INT AUTO_INCREMENT PRIMARY KEY,
                scan_date DATETIME,
                ip VARCHAR(15),
                hostname VARCHAR(255),
                ports TEXT,
                scan_type VARCHAR(50)
            )
            ''')
            
            # Insertion des résultats
            scan_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            scan_type = self.scan_type.get()
            
            for ip, data in scan_results.items():
                # Formatage des ports pour stockage
                ports_json = ", ".join([f"{p['port']}/{p['protocol']}" for p in data['ports']])
                
                cursor.execute(
                    'INSERT INTO nmap_results (scan_date, ip, hostname, ports, scan_type) VALUES (%s, %s, %s, %s, %s)',
                    (scan_date, data['ip'], data['hostname'], ports_json, scan_type)
                )
            
            conn.commit()
            cursor.close()
            conn.close()
            return True
        except mysql.connector.Error as err:
            logging.error(f"Erreur MySQL: {err}")
            raise

    # Fonctions liées à la gestion des sondes
    def register_probe(self):
        # Récupérer le nom d'hôte et l'adresse IP locale
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            
            # Essayer de charger l'ID enregistré précédemment
            probe_id = self.load_probe_id()
            
            if probe_id:
                # Mise à jour d'une sonde existante
                self.update_probe(probe_id, hostname, ip)
            else:
                # Création d'une nouvelle sonde
                self.add_new_probe(hostname, ip)
                
        except Exception as e:
            logging.error(f"Erreur lors de l'enregistrement de la sonde: {e}")
            self.status_var.set("Erreur d'enregistrement")
            messagebox.showerror("Erreur", f"Impossible d'enregistrer la sonde: {e}")
        
            
    def initialize_probe(self):
        """Initialise la sonde : récupère ou enregistre automatiquement si nécessaire."""
        probe_id = self.load_probe_id()

        if probe_id:
            try:
                self.status_var.set("Chargement de la sonde...")
                response = requests.get(f"{self.server_url}?action=get&id={probe_id}", timeout=10)
                response.raise_for_status()
                json_resp = response.json()

                if json_resp.get('success') and json_resp.get('probe'):
                    probe = json_resp['probe']
                    self.probe_id_var.set(str(probe_id))
                    self.probe_status_var.set(probe.get('status', 'inconnu'))
                    self.status_var.set("Sonde existante chargée")
                    self.send_probe_status()
                    return
                else:
                    self.status_var.set("Sonde absente du serveur, enregistrement...")
                    self.delete_probe_id()

            except Exception as e:
                logging.error(f"Erreur récupération sonde: {e}")
                self.status_var.set("Erreur récupération, enregistrement automatique")

        # Aucun ID local ou récupération impossible → on enregistre une nouvelle
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            self.add_new_probe(hostname, ip)
        except Exception as e:
            logging.error(f"Erreur enregistrement automatique: {e}")
            self.status_var.set("Erreur à l'enregistrement")




    def add_new_probe(self, name, ip):
        try:
            self.status_var.set("Enregistrement de la sonde...")

            data = {
                'name': name,
                'ip': ip,
                'status': 'active'
            }

            try:
                response = requests.post(f"{self.server_url}?action=add", data=data, timeout=10)
                response.raise_for_status()  # Vérifie que la requête a réussi (code 200)
            except requests.exceptions.RequestException as e:
                logging.error(f"Erreur réseau: {e}")
                self.status_var.set("Erreur de connexion")
                messagebox.showerror("Erreur", "Impossible de contacter le serveur. Vérifiez votre connexion.")
                return

            try:
                json_resp = response.json()
            except ValueError:
                logging.error("Réponse invalide du serveur (pas un JSON)")
                self.status_var.set("Réponse invalide du serveur")
                messagebox.showerror("Erreur", "Réponse du serveur incorrecte. Contactez l'administrateur.")
                return

            if json_resp.get('success'):
                probe_id = json_resp.get('id')
                self.probe_id_var.set(str(probe_id))
                self.probe_status_var.set("Enregistré")
                self.status_var.set("Sonde enregistrée avec succès")

                self.save_probe_id(probe_id)
                self.send_probe_status()

                messagebox.showinfo("Succès", "Sonde enregistrée avec succès")
            else:
                error_msg = json_resp.get('message', 'Erreur inconnue')
                self.status_var.set(f"Échec: {error_msg}")
                messagebox.showerror("Erreur", f"Échec de l'enregistrement: {error_msg}")

        except Exception as e:
            logging.error(f"Erreur lors de l'ajout de la sonde: {e}")
            self.status_var.set("Erreur de communication")
            messagebox.showerror("Erreur", f"Impossible de communiquer avec le serveur: {e}")

    def update_probe(self, probe_id, name, ip):
        try:
            self.status_var.set("Mise à jour de la sonde...")
            
            # Préparation des données pour l'API
            data = {
                'id': probe_id,
                'name': name,
                'ip': ip,
                'status': 'active'  # Mise à jour du statut
            }
            
            # Requête POST pour mettre à jour la sonde
            response = requests.post(f"{self.server_url}?action=update", data=data)
            json_resp = response.json()
            
            if json_resp.get('success'):
                self.probe_id_var.set(str(probe_id))
                self.probe_status_var.set("Actif")
                self.status_var.set("Sonde mise à jour avec succès")
            else:
                error_msg = json_resp.get('message', 'Erreur inconnue')
                self.status_var.set(f"Échec: {error_msg}")
                messagebox.showerror("Erreur", f"Échec de la mise à jour: {error_msg}")
                
        except Exception as e:
            logging.error(f"Erreur lors de la mise à jour de la sonde: {e}")
            self.status_var.set("Erreur de communication")

    def send_probe_status(self):
        try:
            probe_id = self.load_probe_id()
            
            if not probe_id:
                messagebox.showinfo("Information", "La sonde n'est pas encore enregistrée.")
                return
                
            self.status_var.set("Envoi du statut...")
            
            # Envoi d'une requête ping
            response = requests.post(f"{self.server_url}?action=ping", data={'id': probe_id})
            json_resp = response.json()
            
            if json_resp.get('success'):
                status = "Actif" if json_resp.get('reachable') else "Inactif"
                self.probe_status_var.set(status)
                self.status_var.set(f"Statut envoyé: {status}")
            else:
                error_msg = json_resp.get('message', 'Erreur inconnue')
                self.status_var.set(f"Échec test: {error_msg}")
                
            return json_resp.get('success', False)
                
        except Exception as e:
            logging.error(f"Erreur lors de l'envoi du statut: {e}")
            self.status_var.set("Erreur de communication")
            return False

    def start_status_updater(self):
        # Envoi périodique du statut toutes les 5 minutes
        def status_update_loop():
            while True:
                try:
                    # Vérifier si l'ID de la sonde existe
                    probe_id = self.load_probe_id()
                    if probe_id:
                        success = self.send_probe_status()
                        if success:
                            logging.info("Statut de la sonde mis à jour automatiquement")
                        else:
                            logging.warning("Échec de la mise à jour automatique du statut")
                except Exception as e:
                    logging.error(f"Erreur lors de la mise à jour automatique du statut: {e}")
                
                # Attendre 5 minutes
                time.sleep(300)
        
        # Démarrer le thread de mise à jour
        update_thread = threading.Thread(target=status_update_loop)
        update_thread.daemon = True
        update_thread.start()

    def save_probe_id(self, probe_id):
        try:
            with open('./Services/probe_config.json', 'w') as f:
                json.dump({'probe_id': probe_id}, f)
        except Exception as e:
            logging.error(f"Erreur lors de la sauvegarde de l'ID de la sonde: {e}")

    def load_probe_id(self):
        try:
            if os.path.exists('./Services/probe_config.json'):
                with open('./Services/probe_config.json', 'r') as f:
                    config = json.load(f)
                    probe_id = config.get('probe_id')
                    if probe_id:
                        self.probe_id_var.set(str(probe_id))
                    return probe_id
        except Exception as e:
            logging.error(f"Erreur lors du chargement de l'ID de la sonde: {e}")
        
        return None

    def test_server_connection(self):
        try:
            self.status_var.set("Test de connexion...")
            
            # Test simple avec action get
            response = requests.get(f"{self.server_url}?action=get")
            json_resp = response.json()
            
            if json_resp.get('success'):
                self.status_var.set("Connexion au serveur réussie")
                messagebox.showinfo("Succès", "Connexion au serveur établie avec succès!")
            else:
                error_msg = json_resp.get('message', 'Erreur inconnue')
                self.status_var.set(f"Échec: {error_msg}")
                messagebox.showerror("Erreur", f"Échec de la connexion: {error_msg}")
                
        except Exception as e:
            logging.error(f"Erreur lors du test de connexion au serveur: {e}")
            self.status_var.set("Erreur de communication")
            messagebox.showerror("Erreur", f"Impossible de communiquer avec le serveur: {e}")

    def show_server_config(self):
        # Fenêtre de configuration du serveur
        config_window = tk.Toplevel(self.root)
        config_window.title("Configuration du serveur")
        config_window.geometry("400x150")
        config_window.transient(self.root)
        config_window.grab_set()
        
        # Champs de configuration
        ttk.Label(config_window, text="URL du serveur:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        url_entry = ttk.Entry(config_window, width=40)
        url_entry.grid(row=0, column=1, padx=10, pady=5)
        url_entry.insert(0, self.server_url)
        
        # Boutons
        btn_frame = ttk.Frame(config_window)
        btn_frame.grid(row=1, column=0, columnspan=2, pady=15)
        
        def save_server_config():
            self.server_url = url_entry.get()
            messagebox.showinfo("Succès", "Configuration du serveur enregistrée")
            config_window.destroy()
        
        ttk.Button(btn_frame, text="Enregistrer", command=save_server_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Tester connexion", command=self.test_server_connection).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Annuler", command=config_window.destroy).pack(side=tk.LEFT, padx=5)

   def update_application(self):
    self.status_var.set("Mise à jour en cours...")
    self.progress.start()
    
    def do_update():
        try:
            import subprocess
            repo_dir = os.path.dirname(os.path.abspath(__file__))
            repo_url = 'https://github.com/tfourneau/Harvester.git'
            
            self.update_text_widget("Vérification des mises à jour...\n")
            
            # Configuration de sécurité Git
            subprocess.run(['git', 'config', '--global', 'safe.directory', repo_dir], 
                        capture_output=True, text=True)
            
            if not os.path.exists(os.path.join(repo_dir, '.git')):
                self.update_text_widget("Initialisation du dépôt git...\n")
                git.Repo.init(repo_dir)
                repo = git.Repo(repo_dir)
                origin = repo.create_remote('origin', repo_url)
                
                # Sauvegarde des fichiers existants
                self.update_text_widget("Sauvegarde des fichiers existants...\n")
                backup_dir = os.path.join(repo_dir, 'backup_files')
                os.makedirs(backup_dir, exist_ok=True)
                for item in os.listdir(repo_dir):
                    if item != '.git' and item != 'backup_files':
                        src = os.path.join(repo_dir, item)
                        dst = os.path.join(backup_dir, item)
                        if os.path.isfile(src):
                            shutil.copy2(src, dst)
                
                # Téléchargement initial
                self.update_text_widget("Premier téléchargement du code source...\n")
                origin.fetch()
                
                # Forcer le checkout en supprimant les fichiers conflictuels
                for untracked_file in ['client.py', 'server.py']:
                    file_path = os.path.join(repo_dir, untracked_file)
                    if os.path.exists(file_path):
                        shutil.move(file_path, os.path.join(backup_dir, untracked_file))
                
                # Checkout initial
                repo.git.checkout('--track', 'origin/main')
                self.update_text_widget("Installation initiale terminée.\n")
            else:
                repo = git.Repo(repo_dir)
                origin = repo.remote('origin')
                
                # Déplacer les fichiers non suivis qui pourraient causer des conflits
                untracked_files = repo.untracked_files
                if untracked_files:
                    self.update_text_widget(f"Déplacement des fichiers non suivis...\n")
                    backup_dir = os.path.join(repo_dir, 'backup_files')
                    os.makedirs(backup_dir, exist_ok=True)
                    for file in untracked_files:
                        src = os.path.join(repo_dir, file)
                        dst = os.path.join(backup_dir, file)
                        os.makedirs(os.path.dirname(dst), exist_ok=True)
                        shutil.move(src, dst)
                
                # Forcer la mise à jour en réinitialisant les modifications locales
                self.update_text_widget("Réinitialisation des modifications locales...\n")
                repo.git.reset('--hard')
                
                # Suite de la mise à jour
                origin.fetch()
                current_branch = repo.active_branch
                if current_branch.name in [ref.remote_head for ref in origin.refs]:
                    origin.pull()
                    self.update_text_widget("Mise à jour terminée.\n")
                    self.root.after(0, lambda: messagebox.showinfo(
                        "Mise à jour terminée", 
                        "L'application a été mise à jour. Veuillez la redémarrer."
                    ))
                else:
                    repo.git.checkout('--track', 'origin/main')
                    self.update_text_widget("Branche principale configurée.\n")
        
        except Exception as e:
            self.update_text_widget(f"Erreur lors de la mise à jour: {e}\n")
            logging.error(f"Erreur lors de la mise à jour: {e}")
        finally:
            self.root.after(0, lambda: self.status_var.set("Prêt"))
            self.root.after(0, self.progress.stop)
    
    update_thread = threading.Thread(target=do_update)
    update_thread.daemon = True
    update_thread.start()


    def export_results(self):
        if not self.scan_results:
            messagebox.showinfo("Information", "Aucun résultat de scan à exporter.")
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{timestamp}.txt"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"Rapport de scan Harvester - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 50 + "\n\n")
                
                for ip, data in self.scan_results.items():
                    f.write(f"Hôte: {ip}\n")
                    f.write(f"Nom d'hôte: {data['hostname']}\n")
                    f.write(f"Ports ouverts: {len(data['ports'])}\n")
                    f.write("-" * 30 + "\n")
                    
                    for port_info in data['ports']:
                        f.write(f"  {port_info['port']}/{port_info['protocol']}: {port_info['service']} ({port_info['state']})\n")
                    
                    f.write("\n")
            
            messagebox.showinfo("Exportation réussie", f"Les résultats ont été exportés dans {filename}")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'exportation: {e}")

    def show_db_config(self):
        # Fenêtre de configuration de la base de données
        config_window = tk.Toplevel(self.root)
        config_window.title("Configuration de la base de données")
        config_window.geometry("400x250")
        config_window.transient(self.root)
        config_window.grab_set()
        
        # Champs de configuration
        ttk.Label(config_window, text="Hôte:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        host_entry = ttk.Entry(config_window, width=30)
        host_entry.grid(row=0, column=1, padx=10, pady=5)
        host_entry.insert(0, "88.198.97.253")
        
        ttk.Label(config_window, text="Port:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        port_entry = ttk.Entry(config_window, width=30)
        port_entry.grid(row=1, column=1, padx=10, pady=5)
        port_entry.insert(0, "3306")
        
        ttk.Label(config_window, text="Base de données:").grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        db_entry = ttk.Entry(config_window, width=30)
        db_entry.grid(row=2, column=1, padx=10, pady=5)
        db_entry.insert(0, "nmap_results_db")
        
        ttk.Label(config_window, text="Utilisateur:").grid(row=3, column=0, sticky=tk.W, padx=10, pady=5)
        user_entry = ttk.Entry(config_window, width=30)
        user_entry.grid(row=3, column=1, padx=10, pady=5)
        user_entry.insert(0, "admin")
        
        ttk.Label(config_window, text="Mot de passe:").grid(row=4, column=0, sticky=tk.W, padx=10, pady=5)
        pass_entry = ttk.Entry(config_window, width=30, show="*")
        pass_entry.grid(row=4, column=1, padx=10, pady=5)
        pass_entry.insert(0, "root")
        
        # Boutons
        btn_frame = ttk.Frame(config_window)
        btn_frame.grid(row=5, column=0, columnspan=2, pady=15)
        
        ttk.Button(btn_frame, text="Tester connexion", command=lambda: self.test_db_connection(
            host_entry.get(), port_entry.get(), db_entry.get(), user_entry.get(), pass_entry.get()
        )).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="Fermer", command=config_window.destroy).pack(side=tk.LEFT, padx=5)

    def test_db_connection(self, host, port, database, user, password):
        try:
            conn = mysql.connector.connect(
                host=host,
                port=int(port),
                database=database,
                user=user,
                password=password
            )
            conn.close()
            messagebox.showinfo("Test réussi", "Connexion à la base de données établie avec succès!")
        except Exception as e:
            messagebox.showerror("Erreur de connexion", f"Impossible de se connecter à la base de données: {e}")

    def show_about(self):
        about_window = tk.Toplevel(self.root)
        about_window.title("À propos de Harvester")
        about_window.geometry("400x300")
        about_window.transient(self.root)
        about_window.grab_set()
        
        ttk.Label(
            about_window, 
            text="Harvester", 
            font=("Arial", 16, "bold")
        ).pack(pady=(20, 5))
        
        ttk.Label(
            about_window, 
            text=f"Version {self.get_application_version()}"
        ).pack(pady=5)
        
        ttk.Label(
            about_window, 
            text="Un outil de scan réseau avec interface graphique",
            wraplength=300
        ).pack(pady=5)
        
        ttk.Label(
            about_window, 
            text="© 2025",
        ).pack(pady=5)
        
        ttk.Button(
            about_window, 
            text="Fermer", 
            command=about_window.destroy
        ).pack(pady=20)

    def get_application_version(self):
        return "1.1.0"

def get_wan_latency(target='google.com', count=5):
    latencies = []
    try:
        for _ in range(count):
            result = subprocess.run(['ping', '-n', '1', target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if "temps=" in result.stdout:
                latency = float(result.stdout.split("temps=")[1].split("ms")[0].strip())
                latencies.append(latency)
            time.sleep(0.2)
        return sum(latencies) / len(latencies) if latencies else None
    except Exception as e:
        logging.error(f"Erreur lors du ping WAN: {e}")
        return None

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = HarvesterApp(root)
        root.mainloop()
    except Exception as e:
        logging.critical(f"Erreur critique de l'application: {e}")
        messagebox.showerror("Erreur critique", f"Une erreur critique est survenue: {e}")

# test
