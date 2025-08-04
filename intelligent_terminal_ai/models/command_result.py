"""
Data models for command results and analysis
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class CommandResult(BaseModel):
    """Result of a terminal command execution"""
    
    command: str = Field(description="The command that was executed")
    success: bool = Field(description="Whether the command succeeded")
    return_code: int = Field(description="Exit code of the command")
    stdout: str = Field(description="Standard output from the command")
    stderr: str = Field(description="Standard error from the command")
    execution_time: float = Field(description="Time taken to execute in seconds")
    timestamp: str = Field(description="ISO timestamp when command was executed")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Additional metadata")


class BrowserResult(BaseModel):
    """Result of a browser automation test"""
    
    url: str = Field(description="URL that was tested")
    final_url: str = Field(description="Final URL after redirects")
    success: bool = Field(description="Whether the page loaded successfully")
    title: str = Field(description="Page title")
    load_time: float = Field(description="Time taken to load the page in seconds")
    page_size: int = Field(description="Size of the page content in bytes")
    screenshot_base64: str = Field(description="Base64 encoded screenshot")
    errors: List[str] = Field(default_factory=list, description="List of errors found")
    elements_found: Dict[str, Any] = Field(default_factory=dict, description="Elements checked for")
    performance_metrics: Dict[str, Any] = Field(default_factory=dict, description="Performance metrics")
    timestamp: str = Field(description="ISO timestamp when test was performed")


class AnalysisResult(BaseModel):
    """Result of AI analysis"""
    
    success: bool = Field(description="Whether the overall operation was successful")
    message: str = Field(description="Summary message of the analysis")
    suggestions: List[str] = Field(default_factory=list, description="List of suggestions for improvement")
    suggested_command: Optional[str] = Field(default=None, description="Suggested corrected command")
    analysis: Optional[str] = Field(default=None, description="Detailed technical analysis")
    confidence: Optional[float] = Field(default=None, description="Confidence score 0-1")
    iterations_used: Optional[int] = Field(default=None, description="Number of iterations used")
    final_command: Optional[str] = Field(default=None, description="Final command that was executed")


class InspectionResult(BaseModel):
    """Result of response inspection"""
    
    url: str = Field(description="URL that was inspected")
    status_code: int = Field(description="HTTP status code")
    content_type: str = Field(description="Content type of the response")
    response_size: int = Field(description="Size of the response in bytes")
    issues: List[Dict[str, Any]] = Field(default_factory=list, description="Issues found")
    recommendations: List[str] = Field(default_factory=list, description="Recommendations")
    security_score: float = Field(description="Security score 0-100")
    performance_score: float = Field(description="Performance score 0-100")
    timestamp: str = Field(description="ISO timestamp when inspection was performed")


class SessionState(BaseModel):
    """State of an interactive session"""
    
    session_id: str = Field(description="Unique session identifier")
    start_time: str = Field(description="Session start timestamp")
    command_count: int = Field(default=0, description="Number of commands executed")
    success_count: int = Field(default=0, description="Number of successful commands")
    current_context: Dict[str, Any] = Field(default_factory=dict, description="Current session context")
    history: List[Dict[str, Any]] = Field(default_factory=list, description="Session history")


class TaskResult(BaseModel):
    """Result of a complex task execution"""
    
    task_id: str = Field(description="Unique task identifier")
    task_description: str = Field(description="Description of the task")
    success: bool = Field(description="Whether the task completed successfully")
    steps_completed: int = Field(description="Number of steps completed")
    total_steps: int = Field(description="Total number of steps")
    execution_time: float = Field(description="Total execution time in seconds")
    results: List[CommandResult] = Field(default_factory=list, description="Individual command results")
    final_analysis: AnalysisResult = Field(description="Final analysis of the task")
    timestamp: str = Field(description="ISO timestamp when task was completed")
