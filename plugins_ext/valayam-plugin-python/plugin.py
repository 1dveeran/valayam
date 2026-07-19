import sys
import time
import json
import socket
from concurrent import futures

import grpc
import plugin_pb2
import plugin_pb2_grpc

class PluginService(plugin_pb2_grpc.PluginServiceServicer):
    def Init(self, request, context):
        return plugin_pb2.InitResponse(success=True, error_message="")

    def ValidateConfig(self, request, context):
        return plugin_pb2.ValidateConfigResponse(valid=True, error_message="")

    def Execute(self, request, context):
        # We received request.target and request.template_json
        # Yield findings as JSON strings
        
        finding = {
            "template_id": "python-example",
            "template_name": "Python Example Plugin",
            "severity": "info",
            "target": request.target,
            "matched_at": "example match from Python",
            "metadata": {}
        }
        
        yield plugin_pb2.ExecuteResponse(finding_json=json.dumps(finding))

    def Shutdown(self, request, context):
        # Graceful shutdown could stop the server, but the engine will kill the process anyway
        return plugin_pb2.ShutdownResponse(success=True)

def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', 0))
    port = s.getsockname()[1]
    s.close()
    return port

def serve():
    port = get_free_port()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    plugin_pb2_grpc.add_PluginServiceServicer_to_server(PluginService(), server)
    server.add_insecure_port(f'127.0.0.1:{port}')
    server.start()
    
    # HashiCorp go-plugin protocol handshake
    print(f"1|plugin|tcp|127.0.0.1:{port}|grpc", flush=True)
    
    server.wait_for_termination()

if __name__ == '__main__':
    serve()
