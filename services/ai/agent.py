import os
import json
import yaml
import tempfile
from pydantic import BaseModel, Field
from typing import List, Dict, Any
from valayam_client import ValayamClient
from openai import OpenAI

class VulnerabilityTemplate(BaseModel):
    id: str
    info: dict
    requests: list = []
    network: list = []
    dns: list = []
    tls: list = []
    scripts: list = []

class AIAgent:
    def __init__(self, workspace_dir: str, api_key: str = None):
        self.client = ValayamClient(workspace_dir)
        self.llm = OpenAI(api_key=api_key or os.environ.get("OPENAI_API_KEY", "dummy-key"))

    def generate_template(self, instruction: str) -> dict:
        """Uses LLM to dynamically generate a Valayam DSL template based on the instruction."""
        prompt = f"""
You are a security expert. Generate a Valayam scanner template in YAML for the following goal:
"{instruction}"

Return ONLY valid YAML. No markdown formatting.
        """
        
        # Note: In a real scenario, this would call the LLM API. 
        # For demonstration (MVP), if the API key is missing or dummy, we return a fallback.
        try:
            response = self.llm.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0
            )
            yaml_content = response.choices[0].message.content.strip()
            if yaml_content.startswith("```yaml"):
                yaml_content = yaml_content[7:]
            if yaml_content.endswith("```"):
                yaml_content = yaml_content[:-3]
                
            return yaml.safe_load(yaml_content)
        except Exception as e:
            print(f"[!] LLM Generation failed: {e}. Falling back to default template.")
            # Fallback template for testing without a real OpenAI key
            return {
                "id": "ai-generated-test",
                "info": {
                    "name": "AI Generated Default Scan",
                    "severity": "Info",
                    "description": "Fallback template for MVP"
                },
                "requests": [{
                    "method": "GET",
                    "path": "/",
                    "matchers": [{
                        "type": "status",
                        "part": "status",
                        "status": [200]
                    }]
                }]
            }

    def execute_goal(self, target: str, instruction: str) -> List[Dict[str, Any]]:
        """Generates a template for the goal and executes it against the target."""
        print(f"[*] Goal: {instruction}")
        print(f"[*] Target: {target}")
        
        print("[*] Generating template...")
        template_dict = self.generate_template(instruction)
        
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as tmp:
            yaml.dump(template_dict, tmp)
            template_path = tmp.name
            
        print(f"[*] Executing template (saved at {template_path})...")
        try:
            results = self.client.run_scan(target, template_path)
            return results
        finally:
            if os.path.exists(template_path):
                os.remove(template_path)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Valayam AI Agent")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-i", "--instruction", required=True, help="Security objective")
    args = parser.parse_args()

    # The Rust workspace is two directories up (relative to services/ai)
    workspace_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    
    agent = AIAgent(workspace_dir)
    findings = agent.execute_goal(args.url, args.instruction)
    
    print("\n[+] AI Agent Findings:")
    print(json.dumps(findings, indent=2))
