from valayam_sdk import PluginServer, ScannerPlugin, Finding

class MycustomscannerScanner(ScannerPlugin):
def execute(self, template, context):
target = context.get("target_url", "")
return [
Finding(title="Sample Finding", severity="INFO", description=f"Scanned {target}")
]

if __name__ == "__main__":
PluginServer(MycustomscannerScanner()).serve()
