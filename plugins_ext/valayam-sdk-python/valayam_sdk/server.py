import sys
import grpc
from concurrent import futures
import socket
from typing import Dict, List, Optional, Any
import json

from . import plugin_pb2
from . import plugin_pb2_grpc

class Finding:
    def __init__(self, title: str, severity: str, description: str = ""):
        self.title = title
        self.severity = severity
        self.description = description

class ScannerPlugin:
    """Base class for all Valayam Python Plugins"""
    
    def name(self) -> str:
        return self.__class__.__name__

    def version(self) -> str:
        return "1.0.0"

    def execute(self, template: Dict[str, Any], context: Dict[str, str]) -> List[Finding]:
        """Override this method to implement security scanning logic"""
        return []

class _PluginServicer(plugin_pb2_grpc.ScanPluginServicer):
    def __init__(self, plugin: ScannerPlugin):
        self.plugin = plugin

    def Init(self, request, context):
        return plugin_pb2.InitResponse(success=True)

    def Execute(self, request, context):
        try:
            template = json.loads(request.template_json)
            scan_ctx = json.loads(request.context_json)
            
            findings = self.plugin.execute(template, scan_ctx)
            
            for f in findings:
                yield plugin_pb2.ExecuteResponse(
                    finding=plugin_pb2.Finding(
                        title=f.title,
                        severity=f.severity,
                        description=f.description
                    )
                )
        except Exception as e:
            # Emitting an error finding if execution fails completely
            yield plugin_pb2.ExecuteResponse(
                finding=plugin_pb2.Finding(
                    title=f"Plugin Execution Error: {self.plugin.name()}",
                    severity="INFO",
                    description=str(e)
                )
            )

    def ValidateConfig(self, request, context):
        return plugin_pb2.ValidateConfigResponse(valid=True)

    def Shutdown(self, request, context):
        return plugin_pb2.ShutdownResponse(success=True)

class PluginServer:
    def __init__(self, plugin: ScannerPlugin):
        self.plugin = plugin

    def _get_free_port(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def serve(self):
        port = self._get_free_port()
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        plugin_pb2_grpc.add_ScanPluginServicer_to_server(_PluginServicer(self.plugin), server)
        server.add_insecure_port(f'127.0.0.1:{port}')
        server.start()
        
        # HashiCorp go-plugin handshake
        print(f"1|plugin|tcp|127.0.0.1:{port}|grpc")
        sys.stdout.flush()
        
        server.wait_for_termination()
