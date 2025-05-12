#!/usr/bin/env python3
"""
NASM Compiler Server for Last Epoch Hook System

This server accepts assembly code via HTTP POST requests, compiles it using NASM,
and returns the compiled binary as a base64-encoded string.

Usage:
  python3 compiler_server.py [--port PORT] [--host HOST]

Options:
  --port PORT    Port to run the server on (default: 8765)
  --host HOST    Host to bind the server to (default: 192.168.88.38)
"""

import argparse
import base64
import json
import logging
import os
import subprocess
import tempfile
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional, Tuple


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
logger = logging.getLogger('compiler_server')


class CompilationError(Exception):
    """Exception raised for errors during the compilation process."""


def compile_assembly(asm_code: str, format: str = 'elf64') -> bytes:
    """
    Compile assembly code using NASM.

    Args:
        asm_code: The assembly code to compile
        format: Output format (default: elf64)

    Returns:
        The compiled binary data

    Raises:
        CompilationError: If compilation fails
    """
    # Create temporary files
    with (
        tempfile.NamedTemporaryFile(suffix='.asm', delete=False) as asm_file,
        tempfile.NamedTemporaryFile(suffix='.o', delete=False) as obj_file,
    ):
        asm_path = asm_file.name
        obj_path = obj_file.name

    try:
        # Write assembly code to temporary file
        with open(asm_path, 'w') as f:
            f.write(asm_code)

        logger.info(f'Compiling code \n: {asm_code}')

        # Compile with NASM
        logger.info(f'Compiling assembly code using format: {format}')
        cmd = ['nasm', '-o', obj_path, '-f', format, '-g', '-w+all', asm_path]

        logger.info(f"Running command: {' '.join(cmd)}")
        process = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False
        )

        if process.returncode != 0:
            error_msg = f'NASM compilation failed: {process.stderr}'
            logger.error(error_msg)
            raise CompilationError(error_msg)

        # Read compiled binary
        with open(obj_path, 'rb') as f:
            binary_data = f.read()

        return binary_data

    finally:
        # Clean up temporary files
        for path in [asm_path, obj_path]:
            try:
                if os.path.exists(path):
                    os.unlink(path)
            except Exception as e:
                logger.warning(f'Failed to delete temporary file {path}: {e}')


class CompilerHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the compiler server."""

    def _send_error_response(self, status_code: int, message: str) -> None:
        """Send an error response in JSON format."""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

        response = {'success': False, 'error': message}

        self.wfile.write(json.dumps(response).encode('utf-8'))

    def _send_success_response(self, data: Dict[str, Any]) -> None:
        """Send a success response in JSON format."""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

        response = {'success': True, **data}

        self.wfile.write(json.dumps(response).encode('utf-8'))

    def _parse_request(self) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Parse the incoming JSON request."""
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')

        try:
            json_data = json.loads(post_data)
            return json_data, None
        except json.JSONDecodeError as e:
            return None, f'Invalid JSON: {e!s}'

    def do_POST(self):
        """Handle POST requests for assembly compilation."""
        if self.path == '/compile':
            request_data, error = self._parse_request()

            if error:
                self._send_error_response(400, error)
                return

            # Validate request
            if 'asm_code' not in request_data:
                self._send_error_response(400, "Missing 'asm_code' parameter")
                return

            asm_code = request_data['asm_code']
            format = request_data.get('format', 'elf64')

            # Validate format
            valid_formats = ['elf64', 'elf32', 'win32', 'win64', 'macho64', 'bin']
            if format not in valid_formats:
                self._send_error_response(
                    400, f"Invalid format. Must be one of: {', '.join(valid_formats)}"
                )
                return

            try:
                # Compile the assembly code
                start_time = time.time()
                binary_data = compile_assembly(asm_code, format)

                # Encode binary as base64
                base64_data = base64.b64encode(binary_data).decode('utf-8')

                elapsed_time = time.time() - start_time
                logger.info(
                    f'Compilation successful: {len(binary_data)} bytes in {elapsed_time:.2f}s'
                )

                # Send response
                self._send_success_response(
                    {'binary': base64_data, 'size': len(binary_data), 'format': format}
                )

            except CompilationError as e:
                self._send_error_response(400, str(e))
            except Exception as e:
                logger.exception('Unexpected error during compilation')
                self._send_error_response(500, f'Server error: {e!s}')
        else:
            self._send_error_response(404, 'Not found')

    def do_GET(self):
        """Handle GET requests to check server status."""
        if self.path == '/status':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()

            response = {'status': 'ok', 'version': '1.0', 'server': 'NASM Compiler Server'}

            self.wfile.write(json.dumps(response).encode('utf-8'))
        else:
            self._send_error_response(404, 'Not found')


def main():
    """Start the compiler server."""
    parser = argparse.ArgumentParser(description='NASM Compiler Server')
    parser.add_argument('--port', type=int, default=8765, help='Port to run the server on')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind the server to')

    args = parser.parse_args()

    # Check if NASM is installed
    try:
        subprocess.run(
            ['nasm', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.error(
            'NASM is not installed or not in PATH. Please install NASM to use this server.'
        )
        exit(1)

    server_address = (args.host, args.port)
    httpd = HTTPServer(server_address, CompilerHandler)

    logger.info(f'Starting NASM compiler server on http://{args.host}:{args.port}')
    logger.info('Press Ctrl+C to stop the server')

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info('Server stopped by user')
    finally:
        httpd.server_close()
        logger.info('Server shutdown complete')


if __name__ == '__main__':
    main()
