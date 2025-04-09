#!/usr/bin/env python3
import os
import sys
import shutil
import subprocess
import logging
import argparse
from datetime import datetime

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('harvester_sync.log')
    ]
)
logger = logging.getLogger('harvester_sync')

def parse_arguments():
    parser = argparse.ArgumentParser(description='Synchronise les fichiers Harvester entre le dépôt et l\'application locale')
    parser.add_argument('--repo', required=True, help='URL du dépôt Git')
    parser.add_argument('--branch', default='main', help='Branche à utiliser')
    parser.add_argument('--app-dir', required=True, help='Chemin vers le répertoire de l\'application locale')
    parser.add_argument('--backup', action='store_true', help='Effectuer une sauvegarde avant la synchronisation')
    return parser.parse_args()

def execute_command(command):
    """Exécute une commande shell et journalise le résultat"""
    logger.info(f"Exécution: {' '.join(command)}")
    try:
        result = subprocess.run(command, check=True, text=True, capture_output=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"Erreur lors de l'exécution de la commande: {e}")
        logger.error(f"Sortie d'erreur: {e.stderr}")
        raise

def create_backup(app_dir):
    """Crée une sauvegarde du répertoire de l'application"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = f"{app_dir}_backup_{timestamp}"
    logger.info(f"Création d'une sauvegarde vers {backup_dir}")
    shutil.copytree(app_dir, backup_dir)
    return backup_dir

def clone_repo(repo_url, branch, target_dir):
    """Clone le dépôt Git dans un répertoire temporaire"""
    tmp_dir = f"tmp_harvester_repo_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    logger.info(f"Clonage du dépôt {repo_url} (branche {branch}) vers {tmp_dir}")
    execute_command(["git", "clone", "-b", branch, repo_url, tmp_dir])
    return tmp_dir

def sync_files(source_dir, target_dir, exclude_patterns=None):
    """Synchronise les fichiers entre le dépôt et l'application locale"""
    if exclude_patterns is None:
        exclude_patterns = ['.git', '__pycache__', '*.pyc', '.env', 'node_modules']
    
    # Construction des arguments rsync
    rsync_args = ["rsync", "-av", "--delete"]
    for pattern in exclude_patterns:
        rsync_args.extend(["--exclude", pattern])
    
    # Ajout du slash à la fin du chemin source pour copier le contenu
    source_dir = source_dir.rstrip('/') + '/'
    rsync_args.extend([source_dir, target_dir])
    
    logger.info(f"Synchronisation des fichiers de {source_dir} vers {target_dir}")
    execute_command(rsync_args)

def restart_services(app_dir):
    """Redémarre les services nécessaires après la synchronisation"""
    logger.info("Redémarrage des services Harvester")
    
    # Vérifiez si un script de démarrage existe et exécutez-le
    start_script = os.path.join(app_dir, "scripts", "start.sh")
    if os.path.exists(start_script):
        execute_command(["bash", start_script])
    else:
        # Fallback - ajuster selon votre configuration
        logger.warning("Script de démarrage non trouvé, tentative de redémarrage générique")
        try:
            # Pour une application Docker
            if os.path.exists(os.path.join(app_dir, "docker-compose.yml")):
                execute_command(["docker-compose", "-f", os.path.join(app_dir, "docker-compose.yml"), "down"])
                execute_command(["docker-compose", "-f", os.path.join(app_dir, "docker-compose.yml"), "up", "-d"])
            # Pour une application systemd
            else:
                execute_command(["systemctl", "restart", "harvester.service"])
        except Exception as e:
            logger.error(f"Erreur lors du redémarrage des services: {e}")
            logger.info("Veuillez redémarrer manuellement l'application Harvester")

def main():
    args = parse_arguments()
    
    try:
        # Créer une sauvegarde si demandé
        if args.backup:
            backup_dir = create_backup(args.app_dir)
            logger.info(f"Sauvegarde créée dans {backup_dir}")
        
        # Cloner le dépôt
        tmp_repo_dir = clone_repo(args.repo, args.branch, "tmp_repo")
        
        # Synchroniser les fichiers
        sync_files(tmp_repo_dir, args.app_dir)
        
        # Redémarrer les services
        restart_services(args.app_dir)
        
        # Nettoyer
        logger.info(f"Suppression du répertoire temporaire {tmp_repo_dir}")
        shutil.rmtree(tmp_repo_dir)
        
        logger.info("Synchronisation terminée avec succès")
        return 0
    
    except Exception as e:
        logger.error(f"Erreur lors de la synchronisation: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())