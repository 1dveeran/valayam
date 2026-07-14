import os
import re

base_dir = r'c:\Users\venthan\Desktop\Project\Rust\valayam\crates\valayam-core\src\features'

for root, _, files in os.walk(base_dir):
    for f in files:
        if f == 'executor.rs':
            path = os.path.join(root, f)
            with open(path, 'r', encoding='utf-8') as file:
                content = file.read()
                
            # Only fix files that have the auto-generated loop
            if 'for _template in templates {' in content and 'MVP Implemented' in content:
                content = content.replace('for _template in templates {', 'if let Some(_template) = templates.first() {')
                
                with open(path, 'w', encoding='utf-8') as file:
                    file.write(content)
                print(f'Fixed {path}')
