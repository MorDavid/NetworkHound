#!/usr/bin/env python3
"""
BloodHound API Uploader (Pre‑Ingest Step)

Purpose:
- Prepare BloodHound with the Custom Nodes/Edges model (icons, styles, kind names)
"""

import requests
import json
import argparse
import sys
import logging
from typing import Optional
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def setup_logging(verbose: bool = False) -> None:
    """Setup logging configuration."""
    log_level = logging.DEBUG if verbose else logging.INFO
    
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    logging.basicConfig(
        level=log_level,
        handlers=[console_handler],
        force=True
    )

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='BloodHound API Uploader - Upload model to BloodHound',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
 Examples:
   # Basic usage:
   python update_custom_nodes_to_bloodhound.py -s https://bloodhound.example.com -u admin@domain.com -p password

   # With verbose logging:
   python update_custom_nodes_to_bloodhound.py -s https://bloodhound.example.com -u admin -p pass -v

   # Reset existing custom nodes before upload:

   # This script is a PRE‑INGEST preparation step.
   # It updates only the Custom Nodes/Edges model (no data ingestion).
   python update_custom_nodes_to_bloodhound.py -s https://bloodhound.example.com -u admin -p pass --reset-custom-nodes
        """
    )
    
    # Connection options (required)
    parser.add_argument('-s', '--server', required=True,
                       help='BloodHound server URL (e.g., https://bloodhound.example.com)')
    parser.add_argument('-u', '--username', required=True,
                       help='Username for authentication')
    parser.add_argument('-p', '--password', required=True,
                       help='Password for authentication')
    
    # Optional
    parser.add_argument('-m', '--model', default='model.json',
                       help='Model file to upload (default: model.json)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--reset-custom-nodes', action='store_true',
                       help='Delete all existing custom nodes before uploading new model')
    
    return parser.parse_args()

class BloodHoundUploader:
    """BloodHound API client for uploading model."""
    
    def __init__(self, server_url: str, username: str, password: str):
        self.server_url = server_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session_token: Optional[str] = None
        self.logger = logging.getLogger('bloodhound_uploader')
    
    def login(self) -> bool:
        """Login to BloodHound API."""
        login_url = f"{self.server_url}/api/v2/login"
        
        login_data = {
            "login_method": "secret",
            "username": self.username,
            "secret": self.password
        }
        
        self.logger.info(f"Connecting to {self.server_url}...")
        
        try:
            response = self.session.post(login_url, json=login_data, verify=False)
            response.raise_for_status()
            
            data = response.json()
            
            if 'data' not in data or 'session_token' not in data['data']:
                self.logger.error("Invalid response format from BloodHound")
                return False
            
            self.session_token = data['data']['session_token']
            self.logger.info("Successfully authenticated with BloodHound")
            return True
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to connect to BloodHound: {e}")
            return False
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON response: {e}")
            return False
    
    def get_existing_custom_nodes(self) -> list:
        """Get list of existing custom nodes from BloodHound (visibility/diagnostics)."""
        if not self.session_token:
            self.logger.error("Not authenticated. Please login first.")
            return []
        
        list_url = f"{self.server_url}/api/v2/custom-nodes"
        
        headers = {
            'Authorization': f'Bearer {self.session_token}'
        }
        
        try:
            self.logger.info("Fetching existing custom nodes...")
            response = self.session.get(list_url, headers=headers, verify=False)
            response.raise_for_status()
            
            data = response.json()
            
            if 'data' not in data:
                self.logger.error("Invalid response format from BloodHound")
                return []
            
            custom_nodes = data['data']
            self.logger.info(f"Found {len(custom_nodes)} existing custom nodes")
            return custom_nodes
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to fetch custom nodes: {e}")
            return []
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON response: {e}")
            return []
    
    def delete_custom_node(self, kind_name: str) -> bool:
        """Delete a specific custom node by kind name."""
        if not self.session_token:
            self.logger.error("Not authenticated. Please login first.")
            return False
        
        delete_url = f"{self.server_url}/api/v2/custom-nodes/{kind_name}"
        
        headers = {
            'Authorization': f'Bearer {self.session_token}'
        }
        
        try:
            response = self.session.delete(delete_url, headers=headers, verify=False)
            response.raise_for_status()
            
            self.logger.info(f"Deleted custom node: {kind_name}")
            return True
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to delete custom node {kind_name}: {e}")
            return False
    
    def reset_custom_nodes(self) -> bool:
        """Delete all existing custom nodes."""
        custom_nodes = self.get_existing_custom_nodes()
        
        if not custom_nodes:
            self.logger.info("No existing custom nodes found")
            return True
        
        self.logger.info(f"Deleting {len(custom_nodes)} existing custom nodes...")
        
        success_count = 0
        for node in custom_nodes:
            kind_name = node.get('kindName')
            if kind_name:
                if self.delete_custom_node(kind_name):
                    success_count += 1
        
        self.logger.info(f"Successfully deleted {success_count}/{len(custom_nodes)} custom nodes")
        return success_count == len(custom_nodes)
    
    def upload_model(self, model_file: str) -> bool:
        """Upload the Custom Nodes/Edges model to BloodHound (pre‑ingest)."""
        if not self.session_token:
            self.logger.error("Not authenticated. Please login first.")
            return False
        
        upload_url = f"{self.server_url}/api/v2/custom-nodes"
        
        # Set authorization header
        headers = {
            'Authorization': f'Bearer {self.session_token}',
            'Content-Type': 'application/json'
        }
        
        try:
            # Read model file
            with open(model_file, 'r', encoding='utf-8') as f:
                model_data = json.load(f)
            
            self.logger.info(
                f"Uploading Custom Nodes/Edges model (pre‑ingest) from {model_file}..."
            )
            
            response = self.session.post(upload_url, json=model_data, headers=headers, verify=False)
            response.raise_for_status()
            
            self.logger.info("Model uploaded successfully. No data was ingested. You can now ingest graph data.")
            return True
            
        except FileNotFoundError:
            self.logger.error(f"Model file not found: {model_file}")
            return False
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in model file: {e}")
            return False
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to upload model: {e}")
            return False
    
    def logout(self) -> bool:
        """Logout from BloodHound API."""
        if not self.session_token:
            self.logger.warning("No active session to logout")
            return True
        
        logout_url = f"{self.server_url}/api/v2/logout"
        
        headers = {
            'Authorization': f'Bearer {self.session_token}'
        }
        
        try:
            response = self.session.post(logout_url, headers=headers, verify=False)
            response.raise_for_status()
            
            self.logger.info("Successfully logged out from BloodHound")
            self.session_token = None
            return True
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to logout: {e}")
            return False
    
    def close(self):
        """Close the session."""
        self.session.close()

def main():
    """Main entry point."""
    args = parse_arguments()
    
    # Setup logging
    setup_logging(verbose=args.verbose)
    logger = logging.getLogger('bloodhound_uploader')
    
    logger.info("Preparing BloodHound Custom Nodes model (pre‑ingest). This does not upload any data.")
    
    # Create uploader instance
    uploader = BloodHoundUploader(args.server, args.username, args.password)
    
    try:
        # Login
        if not uploader.login():
            logger.error("Failed to authenticate with BloodHound")
            sys.exit(1)
        
        # Reset custom nodes if requested
        if args.reset_custom_nodes:
            if not uploader.reset_custom_nodes():
                logger.error("Failed to reset custom nodes")
                sys.exit(1)
        
        # Upload model
        if not uploader.upload_model(args.model):
            logger.error("Failed to upload model")
            sys.exit(1)
        
        logger.info("Pre‑ingest preparation completed. Proceed to ingest the graph JSON.")
        
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
    finally:
        # Always logout
        uploader.logout()
        uploader.close()

if __name__ == "__main__":
    main()