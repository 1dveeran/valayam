import subprocess
import tempfile
import json
import os
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class ValayamClient:
    def __init__(self, workspace_dir: str):
        self.workspace_dir = workspace_dir

    def run_scan(self, target: str, template_path: str) -> List[Dict[str, Any]]:
        """
        Executes valayam-cli against a target using the specified template path.
        Returns a list of finding objects.
        """
        findings = []
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            output_file = tmp.name
        
        try:
            cmd = [
                "cargo", "run", "--bin", "valayam-cli", "--",
                "-u", target,
                "-t", template_path,
                "-o", output_file
            ]
            
            logger.info(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                cwd=self.workspace_dir,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                logger.error(f"Valayam scan failed:\n{result.stderr}")
            
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, "r") as f:
                    for line in f:
                        if line.strip():
                            findings.append(json.loads(line.strip()))
                            
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)
                
        return findings
