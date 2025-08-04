"""
Terminal command executor with error capture and analysis
"""

import asyncio
import subprocess
import shlex
import os
import sys
from typing import Dict, Any, Optional, List
import aiohttp
import json
from datetime import datetime

from ..models.command_result import CommandResult
from ..utils.logger import setup_logger


class TerminalExecutor:
    """
    Executes terminal commands and captures detailed output, errors, and metadata
    """
    
    def __init__(self, timeout: int = 30):
        """
        Initialize the terminal executor
        
        Args:
            timeout: Command timeout in seconds
        """
        self.timeout = timeout
        self.logger = setup_logger(__name__)
        self.command_history: List[Dict[str, Any]] = []
    
    async def execute_command(self, command: str, 
                            cwd: Optional[str] = None,
                            env: Optional[Dict[str, str]] = None) -> CommandResult:
        """
        Execute a terminal command asynchronously
        
        Args:
            command: Command to execute
            cwd: Working directory
            env: Environment variables
            
        Returns:
            CommandResult with execution details
        """
        self.logger.info(f"Executing command: {command}")
        
        start_time = datetime.now()
        
        try:
            # Prepare environment
            full_env = os.environ.copy()
            if env:
                full_env.update(env)
            
            # Execute command
            if sys.platform == "win32":
                # Windows-specific execution
                process = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=cwd,
                    env=full_env
                )
            else:
                # Unix-like systems
                args = shlex.split(command)
                process = await asyncio.create_subprocess_exec(
                    *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=cwd,
                    env=full_env
                )
            
            # Wait for completion with timeout
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=self.timeout
            )
            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            # Decode output
            stdout_text = stdout.decode('utf-8', errors='replace') if stdout else ""
            stderr_text = stderr.decode('utf-8', errors='replace') if stderr else ""
            
            # Determine success
            success = process.returncode == 0
            
            result = CommandResult(
                command=command,
                success=success,
                return_code=process.returncode,
                stdout=stdout_text,
                stderr=stderr_text,
                execution_time=execution_time,
                timestamp=start_time.isoformat()
            )
            
            # Log to history
            self.command_history.append({
                "command": command,
                "result": result.dict(),
                "timestamp": start_time.isoformat()
            })
            
            if success:
                self.logger.info(f"Command completed successfully in {execution_time:.2f}s")
            else:
                self.logger.warning(f"Command failed with return code {process.returncode}")
            
            return result
            
        except asyncio.TimeoutError:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"Command timed out after {self.timeout}s")
            
            return CommandResult(
                command=command,
                success=False,
                return_code=-1,
                stdout="",
                stderr=f"Command timed out after {self.timeout} seconds",
                execution_time=execution_time,
                timestamp=start_time.isoformat()
            )
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"Error executing command: {e}")
            
            return CommandResult(
                command=command,
                success=False,
                return_code=-1,
                stdout="",
                stderr=f"Execution error: {str(e)}",
                execution_time=execution_time,
                timestamp=start_time.isoformat()
            )
    
    async def execute_api_request(self, 
                                url: str,
                                method: str = "GET",
                                headers: Optional[Dict[str, str]] = None,
                                data: Optional[Dict[str, Any]] = None,
                                timeout: int = 30) -> CommandResult:
        """
        Execute an API request and return as CommandResult
        
        Args:
            url: API endpoint URL
            method: HTTP method
            headers: Request headers
            data: Request data
            timeout: Request timeout
            
        Returns:
            CommandResult with API response details
        """
        self.logger.info(f"Making API request: {method} {url}")
        
        start_time = datetime.now()
        command = f"{method} {url}"
        
        try:
            async with aiohttp.ClientSession() as session:
                kwargs = {
                    'url': url,
                    'method': method.upper(),
                    'timeout': aiohttp.ClientTimeout(total=timeout)
                }
                
                if headers:
                    kwargs['headers'] = headers
                
                if data:
                    if method.upper() in ['POST', 'PUT', 'PATCH']:
                        kwargs['json'] = data
                
                async with session.request(**kwargs) as response:
                    response_text = await response.text()
                    execution_time = (datetime.now() - start_time).total_seconds()
                    
                    # Try to format JSON response nicely
                    try:
                        json_data = await response.json()
                        formatted_response = json.dumps(json_data, indent=2)
                    except:
                        formatted_response = response_text
                    
                    success = 200 <= response.status < 400
                    
                    result = CommandResult(
                        command=command,
                        success=success,
                        return_code=response.status,
                        stdout=formatted_response,
                        stderr="" if success else f"HTTP {response.status}: {response.reason}",
                        execution_time=execution_time,
                        timestamp=start_time.isoformat(),
                        metadata={
                            "url": url,
                            "method": method,
                            "status_code": response.status,
                            "headers": dict(response.headers),
                            "content_type": response.content_type
                        }
                    )
                    
                    if success:
                        self.logger.info(f"API request successful: {response.status}")
                    else:
                        self.logger.warning(f"API request failed: {response.status}")
                    
                    return result
                    
        except asyncio.TimeoutError:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"API request timed out after {timeout}s")
            
            return CommandResult(
                command=command,
                success=False,
                return_code=-1,
                stdout="",
                stderr=f"Request timed out after {timeout} seconds",
                execution_time=execution_time,
                timestamp=start_time.isoformat()
            )
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"Error making API request: {e}")
            
            return CommandResult(
                command=command,
                success=False,
                return_code=-1,
                stdout="",
                stderr=f"Request error: {str(e)}",
                execution_time=execution_time,
                timestamp=start_time.isoformat()
            )
    
    def get_command_history(self) -> List[Dict[str, Any]]:
        """Get the command execution history"""
        return self.command_history.copy()
    
    def clear_history(self):
        """Clear the command history"""
        self.command_history.clear()
        self.logger.info("Command history cleared")
