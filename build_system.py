#!/usr/bin/env python3
"""
Auto-Build System for GitHub Actions Integration
===============================================
Handles automated building of Python scripts into EXE files using GitHub Actions
"""

import os
import json
import logging
import base64
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import hashlib
import uuid

logger = logging.getLogger(__name__)


class AutoBuildSystem:
    """
    Automated build system that integrates with GitHub Actions to build Python scripts into EXE files
    """
    
    def __init__(self):
        """Initialize the build system with GitHub configuration"""
        self.github_token = os.environ.get('GITHUB_TOKEN')
        self.github_repo = os.environ.get('GITHUB_REPO', 'alexandrosh8/pdf-license-server')
        self.github_branch = os.environ.get('GITHUB_BRANCH', 'main')
        self.base_url = "https://api.github.com"
        
        if not self.github_token:
            logger.warning("GITHUB_TOKEN not set - GitHub integration disabled")
        
        self.headers = {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json"
        } if self.github_token else {}
    
    def _make_github_request(self, method: str, endpoint: str, data: dict = None) -> dict:
        """Make a request to GitHub API with proper error handling"""
        if not self.github_token:
            return {"error": "GitHub integration not configured"}
        
        url = f"{self.base_url}/repos/{self.github_repo}{endpoint}"
        
        try:
            response = requests.request(method, url, headers=self.headers, json=data, timeout=30)
            
            if response.status_code == 404:
                return {"error": "Repository not found or access denied"}
            elif response.status_code == 401:
                return {"error": "Invalid GitHub token"}
            elif not response.ok:
                return {"error": f"GitHub API error: {response.status_code} - {response.text}"}
            
            return response.json() if response.text else {}
        
        except requests.RequestException as e:
            logger.error(f"GitHub API request failed: {e}")
            return {"error": f"Request failed: {str(e)}"}
    
    def upload_script_and_trigger_build(
        self, 
        script_content: str, 
        script_name: str, 
        version: str, 
        build_config: dict
    ) -> dict:
        """
        Upload a Python script to GitHub and trigger automated build
        
        Args:
            script_content: Python script content as string
            script_name: Name of the script file
            version: Version number for the build
            build_config: Additional build configuration
        
        Returns:
            dict: Result with success status and details
        """
        try:
            if not self.github_token:
                return {
                    "success": False,
                    "error": "GitHub integration not configured. Please set GITHUB_TOKEN environment variable."
                }
            
            # Create workflow file content for GitHub Actions
            workflow_content = self._create_workflow_file(script_name, version, build_config)
            
            # Upload the script file
            script_upload = self._upload_file_to_github(
                f"scripts/{script_name}",
                script_content,
                f"Upload script {script_name} for version {version}"
            )
            
            if "error" in script_upload:
                return {"success": False, "error": f"Script upload failed: {script_upload['error']}"}
            
            # Upload the workflow file
            workflow_upload = self._upload_file_to_github(
                f".github/workflows/build-{version}.yml",
                workflow_content,
                f"Add build workflow for version {version}"
            )
            
            if "error" in workflow_upload:
                return {"success": False, "error": f"Workflow upload failed: {workflow_upload['error']}"}
            
            # Create a release tag to trigger the workflow
            tag_result = self._create_release_tag(version, build_config)
            
            return {
                "success": True,
                "version": version,
                "script_sha": script_upload.get("commit", {}).get("sha"),
                "workflow_sha": workflow_upload.get("commit", {}).get("sha"),
                "tag": tag_result.get("tag_name"),
                "message": f"Build triggered for version {version}"
            }
        
        except Exception as e:
            logger.error(f"Build trigger failed: {e}")
            return {"success": False, "error": f"Build trigger failed: {str(e)}"}
    
    def _upload_file_to_github(self, file_path: str, content: str, commit_message: str) -> dict:
        """Upload a file to GitHub repository"""
        # First, try to get the existing file to get its SHA (needed for updates)
        get_result = self._make_github_request("GET", f"/contents/{file_path}")
        
        file_data = {
            "message": commit_message,
            "content": base64.b64encode(content.encode('utf-8')).decode('utf-8'),
            "branch": self.github_branch
        }
        
        # If file exists, include its SHA for update
        if "sha" in get_result and "error" not in get_result:
            file_data["sha"] = get_result["sha"]
        
        return self._make_github_request("PUT", f"/contents/{file_path}", file_data)
    
    def _create_workflow_file(self, script_name: str, version: str, build_config: dict) -> str:
        """Create GitHub Actions workflow file for building the EXE"""
        workflow = {
            "name": f"Build EXE - {version}",
            "on": {
                "push": {
                    "tags": [f"v{version}"]
                },
                "workflow_dispatch": {}
            },
            "jobs": {
                "build": {
                    "runs-on": "windows-latest",
                    "steps": [
                        {
                            "name": "Checkout code",
                            "uses": "actions/checkout@v4"
                        },
                        {
                            "name": "Set up Python",
                            "uses": "actions/setup-python@v4",
                            "with": {
                                "python-version": "3.9"
                            }
                        },
                        {
                            "name": "Install dependencies",
                            "run": "pip install pyinstaller requests"
                        },
                        {
                            "name": "Build EXE",
                            "run": f"pyinstaller --onefile --windowed --name {script_name.replace('.py', '')}-{version} scripts/{script_name}"
                        },
                        {
                            "name": "Create Release",
                            "uses": "softprops/action-gh-release@v1",
                            "with": {
                                "tag_name": f"v{version}",
                                "name": f"Release {version}",
                                "body": build_config.get("description", f"Automated build of {script_name}"),
                                "files": f"dist/{script_name.replace('.py', '')}-{version}.exe"
                            },
                            "env": {
                                "GITHUB_TOKEN": "${{ secrets.GITHUB_TOKEN }}"
                            }
                        }
                    ]
                }
            }
        }
        
        return json.dumps(workflow, indent=2)
    
    def _create_release_tag(self, version: str, build_config: dict) -> dict:
        """Create a release tag to trigger the workflow"""
        tag_data = {
            "tag_name": f"v{version}",
            "target_commitish": self.github_branch,
            "name": f"Release {version}",
            "body": build_config.get("description", f"Automated release {version}"),
            "draft": False,
            "prerelease": False
        }
        
        return self._make_github_request("POST", "/releases", tag_data)
    
    def get_build_status(self, version: str = None) -> dict:
        """
        Get the status of the latest build or a specific version build
        
        Args:
            version: Optional specific version to check
            
        Returns:
            dict: Build status information
        """
        try:
            if not self.github_token:
                return {"error": "GitHub integration not configured"}
            
            # Get workflow runs
            workflow_runs = self._make_github_request("GET", "/actions/runs?per_page=10")
            
            if "error" in workflow_runs:
                return workflow_runs
            
            runs = workflow_runs.get("workflow_runs", [])
            
            if not runs:
                return {
                    "status": "no_builds",
                    "message": "No builds found"
                }
            
            # Find the most recent run (or specific version if provided)
            target_run = None
            if version:
                for run in runs:
                    if f"v{version}" in run.get("head_branch", "") or f"v{version}" in str(run.get("head_sha", "")):
                        target_run = run
                        break
            else:
                target_run = runs[0]  # Most recent
            
            if not target_run:
                return {
                    "status": "not_found",
                    "message": f"No build found for version {version}" if version else "No builds found"
                }
            
            return {
                "status": target_run.get("status", "unknown"),
                "conclusion": target_run.get("conclusion"),
                "html_url": target_run.get("html_url"),
                "created_at": target_run.get("created_at"),
                "updated_at": target_run.get("updated_at"),
                "workflow_id": target_run.get("workflow_id"),
                "run_number": target_run.get("run_number")
            }
        
        except Exception as e:
            logger.error(f"Failed to get build status: {e}")
            return {"error": f"Failed to get build status: {str(e)}"}
    
    def get_latest_release_info(self) -> dict:
        """
        Get information about the latest release
        
        Returns:
            dict: Latest release information
        """
        try:
            if not self.github_token:
                return {"error": "GitHub integration not configured"}
            
            # Get latest release
            latest_release = self._make_github_request("GET", "/releases/latest")
            
            if "error" in latest_release:
                return latest_release
            
            # Process assets to find the EXE file
            assets = latest_release.get("assets", [])
            exe_asset = None
            
            for asset in assets:
                if asset.get("name", "").endswith(".exe"):
                    exe_asset = asset
                    break
            
            release_info = {
                "version": latest_release.get("tag_name", "").replace("v", ""),
                "name": latest_release.get("name"),
                "published_at": latest_release.get("published_at"),
                "html_url": latest_release.get("html_url"),
                "body": latest_release.get("body"),
                "download_count": sum(asset.get("download_count", 0) for asset in assets)
            }
            
            if exe_asset:
                release_info.update({
                    "download_url": exe_asset.get("browser_download_url"),
                    "file_name": exe_asset.get("name"),
                    "file_size": exe_asset.get("size")
                })
            
            return release_info
        
        except Exception as e:
            logger.error(f"Failed to get latest release info: {e}")
            return {"error": f"Failed to get release info: {str(e)}"}


class UpdateNotificationSystem:
    """
    System for managing update notifications to existing client applications
    """
    
    def __init__(self, build_system: AutoBuildSystem):
        """Initialize with a build system instance"""
        self.build_system = build_system
        self.logger = logging.getLogger(__name__)
    
    def check_for_updates(self, current_version: str) -> dict:
        """
        Check if there are updates available for the given version
        
        Args:
            current_version: Current version of the client
            
        Returns:
            dict: Update information
        """
        try:
            latest_release = self.build_system.get_latest_release_info()
            
            if "error" in latest_release:
                return {
                    "update_available": False,
                    "error": latest_release["error"]
                }
            
            latest_version = latest_release.get("version", "0.0.0")
            
            # Simple version comparison (assumes semantic versioning)
            update_available = self._is_version_newer(latest_version, current_version)
            
            result = {
                "update_available": update_available,
                "current_version": current_version,
                "latest_version": latest_version
            }
            
            if update_available:
                result.update({
                    "download_url": latest_release.get("download_url"),
                    "release_notes": latest_release.get("body", ""),
                    "published_at": latest_release.get("published_at"),
                    "file_name": latest_release.get("file_name")
                })
            
            return result
        
        except Exception as e:
            self.logger.error(f"Update check failed: {e}")
            return {
                "update_available": False,
                "error": f"Update check failed: {str(e)}"
            }
    
    def generate_update_notification(self, current_version: str) -> dict:
        """
        Generate a user-friendly update notification
        
        Args:
            current_version: Current version of the client
            
        Returns:
            dict: Notification data for the client
        """
        update_info = self.check_for_updates(current_version)
        
        if update_info.get("update_available"):
            return {
                "type": "update_available",
                "title": "🚀 Update Available",
                "message": f"A new version ({update_info['latest_version']}) is available!",
                "current_version": current_version,
                "latest_version": update_info["latest_version"],
                "download_url": update_info.get("download_url"),
                "release_notes": update_info.get("release_notes", ""),
                "action_text": "Download Update",
                "dismissible": True
            }
        else:
            return {
                "type": "up_to_date",
                "title": "✅ Up to Date",
                "message": f"You have the latest version ({current_version})",
                "current_version": current_version,
                "dismissible": True
            }
    
    def _is_version_newer(self, version1: str, version2: str) -> bool:
        """
        Compare two version strings (semantic versioning)
        
        Returns:
            bool: True if version1 is newer than version2
        """
        try:
            def parse_version(v):
                return list(map(int, v.replace('v', '').split('.')))
            
            v1_parts = parse_version(version1)
            v2_parts = parse_version(version2)
            
            # Pad shorter version with zeros
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            return v1_parts > v2_parts
        
        except (ValueError, AttributeError):
            # Fallback to string comparison if parsing fails
            return version1 > version2
