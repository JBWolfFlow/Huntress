#!/usr/bin/env python3
"""
HTB Runner - Automated HackTheBox Training System
Phase 5.1 Implementation

Orchestrates the complete HTB training loop:
1. Machine selection with progressive difficulty
2. Instance spawning and management
3. Agent execution with full recording
4. Success/failure detection via flag validation
5. Training data collection and storage

Security: All operations are isolated, logged, and rate-limited.
"""

import asyncio
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any
import argparse

import aiohttp
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('htb_runner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class Difficulty(Enum):
    """HTB machine difficulty levels"""
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    INSANE = "insane"


class SessionStatus(Enum):
    """Training session status"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class HTBMachine:
    """HTB machine metadata"""
    id: int
    name: str
    os: str
    difficulty: str
    ip: Optional[str] = None
    retired: bool = True
    user_owns: int = 0
    root_owns: int = 0
    rating: float = 0.0


@dataclass
class TrainingSession:
    """Training session data"""
    session_id: str
    machine: HTBMachine
    start_time: datetime
    end_time: Optional[datetime] = None
    status: SessionStatus = SessionStatus.PENDING
    user_flag: Optional[str] = None
    root_flag: Optional[str] = None
    flags_validated: bool = False
    execution_time: float = 0.0
    tools_used: List[Dict[str, Any]] = field(default_factory=list)
    discoveries: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None


class HTBAPIClient:
    """
    HackTheBox API Client
    
    Handles all HTB API interactions with proper authentication,
    rate limiting, and error handling.
    """
    
    def __init__(self, api_token: str, base_url: str = "https://www.hackthebox.com/api/v4"):
        self.api_token = api_token
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json',
            'User-Agent': 'Huntress-HTB-Runner/1.0'
        })
        self.rate_limit_delay = 1.0  # Seconds between requests
        self.last_request_time = 0.0
    
    async def _rate_limit(self):
        """Enforce rate limiting between requests"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.time()
    
    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make HTTP request with error handling"""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json() if response.content else {}
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error: {e}")
            logger.error(f"Response: {e.response.text if e.response else 'No response'}")
            raise
        except Exception as e:
            logger.error(f"Request failed: {e}")
            raise
    
    async def list_machines(
        self,
        difficulty: Optional[str] = None,
        retired: bool = True,
        limit: int = 100
    ) -> List[HTBMachine]:
        """
        List available HTB machines
        
        Args:
            difficulty: Filter by difficulty (easy, medium, hard, insane)
            retired: Include retired machines (recommended for training)
            limit: Maximum number of machines to return
        
        Returns:
            List of HTBMachine objects
        """
        await self._rate_limit()
        
        params = {
            'retired': 1 if retired else 0,
            'per_page': limit
        }
        
        if difficulty:
            params['difficulty'] = difficulty
        
        logger.info(f"Fetching machines: difficulty={difficulty}, retired={retired}")
        
        try:
            data = self._request('GET', '/machines', params=params)
            
            machines = []
            for item in data.get('data', []):
                machine = HTBMachine(
                    id=item['id'],
                    name=item['name'],
                    os=item.get('os', 'unknown'),
                    difficulty=item.get('difficulty', 'unknown'),
                    retired=item.get('retired', False),
                    user_owns=item.get('user_owns_count', 0),
                    root_owns=item.get('root_owns_count', 0),
                    rating=item.get('rating', 0.0)
                )
                machines.append(machine)
            
            logger.info(f"Found {len(machines)} machines")
            return machines
        except Exception as e:
            logger.error(f"Failed to list machines: {e}")
            return []
    
    async def spawn_machine(self, machine_id: int) -> Optional[str]:
        """
        Spawn HTB machine instance
        
        Args:
            machine_id: Machine ID to spawn
        
        Returns:
            Machine IP address if successful, None otherwise
        """
        await self._rate_limit()
        
        logger.info(f"Spawning machine {machine_id}")
        
        try:
            data = self._request('POST', f'/machines/{machine_id}/spawn')
            ip = data.get('ip')
            
            if ip:
                logger.info(f"Machine spawned successfully: {ip}")
            else:
                logger.warning("Machine spawned but no IP returned")
            
            return ip
        except Exception as e:
            logger.error(f"Failed to spawn machine: {e}")
            return None
    
    async def terminate_machine(self, machine_id: int) -> bool:
        """
        Terminate HTB machine instance
        
        Args:
            machine_id: Machine ID to terminate
        
        Returns:
            True if successful, False otherwise
        """
        await self._rate_limit()
        
        logger.info(f"Terminating machine {machine_id}")
        
        try:
            self._request('POST', f'/machines/{machine_id}/terminate')
            logger.info("Machine terminated successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to terminate machine: {e}")
            return False
    
    async def submit_flag(
        self,
        machine_id: int,
        flag: str,
        difficulty: int = 10
    ) -> Dict[str, Any]:
        """
        Submit flag for validation
        
        Args:
            machine_id: Machine ID
            flag: Flag hash to submit
            difficulty: Flag difficulty (10=user, 20=root)
        
        Returns:
            Validation result with success status
        """
        await self._rate_limit()
        
        logger.info(f"Submitting flag for machine {machine_id}")
        
        try:
            data = self._request(
                'POST',
                f'/machines/{machine_id}/own',
                json={'flag': flag, 'difficulty': difficulty}
            )
            
            success = data.get('success', False) or data.get('status') == 'success'
            
            if success:
                logger.info("Flag validated successfully!")
            else:
                logger.warning(f"Flag validation failed: {data}")
            
            return {
                'success': success,
                'message': data.get('message', ''),
                'data': data
            }
        except Exception as e:
            logger.error(f"Failed to submit flag: {e}")
            return {'success': False, 'message': str(e), 'data': {}}


class MachineSelector:
    """
    Intelligent machine selection for training
    
    Strategy:
    1. Start with Easy machines (build confidence)
    2. Progress to Medium (expand capabilities)
    3. Attempt Hard (push boundaries)
    4. Avoid Insane until 60%+ success rate
    """
    
    def __init__(self, htb_client: HTBAPIClient, data_dir: Path):
        self.htb_client = htb_client
        self.data_dir = data_dir
        self.history_file = data_dir / 'training_history.json'
        self.success_history: List[bool] = []
        self.attempted_machines: set = set()
        
        self._load_history()
    
    def _load_history(self):
        """Load training history from disk"""
        if self.history_file.exists():
            try:
                with open(self.history_file, 'r') as f:
                    data = json.load(f)
                    self.success_history = data.get('success_history', [])
                    self.attempted_machines = set(data.get('attempted_machines', []))
                logger.info(f"Loaded history: {len(self.success_history)} sessions, {len(self.attempted_machines)} machines")
            except Exception as e:
                logger.error(f"Failed to load history: {e}")
    
    def _save_history(self):
        """Save training history to disk"""
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            with open(self.history_file, 'w') as f:
                json.dump({
                    'success_history': self.success_history,
                    'attempted_machines': list(self.attempted_machines),
                    'last_updated': datetime.now().isoformat()
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save history: {e}")
    
    def _calculate_success_rate(self) -> float:
        """Calculate success rate from last 20 attempts"""
        if len(self.success_history) < 5:
            return 0.0
        
        recent = self.success_history[-20:]
        return sum(recent) / len(recent)
    
    def _determine_target_difficulty(self) -> Difficulty:
        """Determine target difficulty based on current performance"""
        success_rate = self._calculate_success_rate()
        
        if success_rate < 0.40:
            return Difficulty.EASY
        elif success_rate < 0.60:
            return Difficulty.MEDIUM
        else:
            return Difficulty.HARD
    
    async def select_next_machine(self) -> Optional[HTBMachine]:
        """
        Select next machine based on current performance
        
        Returns:
            Machine metadata or None if no suitable machine found
        """
        target_difficulty = self._determine_target_difficulty()
        success_rate = self._calculate_success_rate()
        
        logger.info(f"Current success rate: {success_rate:.1%}")
        logger.info(f"Target difficulty: {target_difficulty.value}")
        
        # Fetch available machines
        machines = await self.htb_client.list_machines(
            difficulty=target_difficulty.value,
            retired=True
        )
        
        # Filter out already attempted
        candidates = [m for m in machines if m.id not in self.attempted_machines]
        
        if not candidates:
            logger.warning(f"No new {target_difficulty.value} machines available")
            # Try next difficulty level
            if target_difficulty == Difficulty.EASY:
                machines = await self.htb_client.list_machines(
                    difficulty=Difficulty.MEDIUM.value,
                    retired=True
                )
            elif target_difficulty == Difficulty.MEDIUM:
                machines = await self.htb_client.list_machines(
                    difficulty=Difficulty.HARD.value,
                    retired=True
                )
            
            candidates = [m for m in machines if m.id not in self.attempted_machines]
        
        if not candidates:
            logger.error("No suitable machines available")
            return None
        
        # Select machine (currently random, could be ML-based)
        import random
        selected = random.choice(candidates)
        
        logger.info(f"Selected machine: {selected.name} ({selected.difficulty})")
        return selected
    
    def record_attempt(self, machine_id: int, success: bool):
        """Record training attempt"""
        self.attempted_machines.add(machine_id)
        self.success_history.append(success)
        self._save_history()


class AgentExecutor:
    """
    Wraps Huntress agent execution for HTB machines
    
    Responsibilities:
    - Configure agent for HTB environment
    - Monitor execution progress
    - Collect execution trace
    - Detect success/failure
    """
    
    def __init__(self, huntress_root: Path):
        self.huntress_root = huntress_root
    
    async def execute_hunt(
        self,
        machine_ip: str,
        machine_info: HTBMachine,
        timeout: int = 7200
    ) -> Dict[str, Any]:
        """
        Execute Huntress agent on HTB machine
        
        Args:
            machine_ip: Target IP address
            machine_info: Machine metadata
            timeout: Maximum execution time in seconds
        
        Returns:
            Execution result with success status and collected data
        """
        session_id = f"htb_{machine_info.id}_{int(datetime.now().timestamp())}"
        start_time = datetime.now()
        
        logger.info(f"Starting hunt session: {session_id}")
        logger.info(f"Target: {machine_ip} ({machine_info.name})")
        
        # Create scope file
        scope_file = await self._create_scope_file(machine_ip, session_id)
        
        # Configure agent
        agent_config = {
            'target': machine_ip,
            'scope_file': str(scope_file),
            'mode': 'training',
            'record_all': True,
            'session_id': session_id,
            'max_iterations': 50,
            'timeout': timeout,
        }
        
        # Execute agent via Node.js subprocess
        result = await self._run_agent(agent_config, timeout)
        
        execution_time = (datetime.now() - start_time).total_seconds()
        
        return {
            'success': result.get('success', False),
            'session_id': session_id,
            'machine_info': machine_info,
            'execution_time': execution_time,
            'flags_found': result.get('flags', []),
            'tools_used': result.get('tools_used', []),
            'discoveries': result.get('discoveries', []),
            'recording_path': f"recordings/{session_id}.cast",
            'error': result.get('error')
        }
    
    async def _create_scope_file(self, machine_ip: str, session_id: str) -> Path:
        """Create temporary scope file for HTB machine"""
        scope_path = Path(f"/tmp/htb_scope_{session_id}.txt")
        scope_path.write_text(f"{machine_ip}\n")
        logger.info(f"Created scope file: {scope_path}")
        return scope_path
    
    async def _run_agent(self, config: Dict[str, Any], timeout: int) -> Dict[str, Any]:
        """
        Run Huntress agent as subprocess
        
        Executes: npm run agent -- --config {config_json}
        """
        config_path = Path(f"/tmp/agent_config_{config['session_id']}.json")
        config_path.write_text(json.dumps(config, indent=2))
        
        logger.info(f"Agent config: {config_path}")
        
        try:
            # Execute agent
            process = await asyncio.create_subprocess_exec(
                'npm', 'run', 'agent', '--',
                '--config', str(config_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self.huntress_root)
            )
            
            # Wait with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                logger.error("Agent execution timed out")
                process.kill()
                await process.wait()
                return {
                    'success': False,
                    'error': 'Execution timeout',
                    'stdout': '',
                    'stderr': 'Timeout exceeded'
                }
            
            # Parse result
            try:
                result = json.loads(stdout.decode())
            except json.JSONDecodeError:
                logger.warning("Failed to parse agent output as JSON")
                result = {
                    'success': False,
                    'error': 'Failed to parse agent output',
                    'stdout': stdout.decode(),
                    'stderr': stderr.decode(),
                }
            
            return result
        except Exception as e:
            logger.error(f"Agent execution failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'stdout': '',
                'stderr': str(e)
            }


class HTBRunner:
    """
    Main orchestrator for HTB training loop
    
    Workflow:
    1. Select machine
    2. Spawn instance
    3. Execute agent
    4. Collect data
    5. Store in Qdrant
    6. Cleanup
    """
    
    def __init__(
        self,
        htb_api_token: str,
        huntress_root: Path,
        data_dir: Path
    ):
        self.htb_client = HTBAPIClient(htb_api_token)
        self.selector = MachineSelector(self.htb_client, data_dir)
        self.executor = AgentExecutor(huntress_root)
        self.data_dir = data_dir
        
        # Ensure data directory exists
        self.data_dir.mkdir(parents=True, exist_ok=True)
    
    async def run_single_session(self) -> TrainingSession:
        """
        Run a single HTB training session
        
        Returns:
            TrainingSession with results
        """
        session_start = datetime.now()
        session_id = f"session_{int(session_start.timestamp())}"
        
        logger.info("="*60)
        logger.info(f"Starting training session: {session_id}")
        logger.info("="*60)
        
        try:
            # Step 1: Select machine
            logger.info("Step 1: Selecting HTB machine...")
            machine = await self.selector.select_next_machine()
            
            if not machine:
                raise Exception("No suitable machine available")
            
            logger.info(f"Selected: {machine.name} ({machine.difficulty})")
            
            # Step 2: Spawn instance
            logger.info("Step 2: Spawning HTB instance...")
            machine_ip = await self.htb_client.spawn_machine(machine.id)
            
            if not machine_ip:
                raise Exception("Failed to spawn machine")
            
            machine.ip = machine_ip
            logger.info(f"Instance spawned: {machine_ip}")
            
            # Wait for machine to be ready
            logger.info("Waiting 30s for machine to initialize...")
            await asyncio.sleep(30)
            
            # Step 3: Execute agent
            logger.info("Step 3: Executing Huntress agent...")
            execution_result = await self.executor.execute_hunt(
                machine_ip,
                machine
            )
            
            # Step 4: Detect success and validate flags
            logger.info("Step 4: Validating flags...")
            flags_found = execution_result.get('flags_found', [])
            user_flag = self._extract_flag(flags_found, 'user')
            root_flag = self._extract_flag(flags_found, 'root')
            
            flags_validated = False
            if user_flag:
                result = await self.htb_client.submit_flag(machine.id, user_flag, 10)
                flags_validated = result['success']
            
            if root_flag:
                result = await self.htb_client.submit_flag(machine.id, root_flag, 20)
                flags_validated = flags_validated or result['success']
            
            success = execution_result['success'] and flags_validated
            
            # Step 5: Create training session record
            session = TrainingSession(
                session_id=session_id,
                machine=machine,
                start_time=session_start,
                end_time=datetime.now(),
                status=SessionStatus.SUCCESS if success else SessionStatus.FAILED,
                user_flag=user_flag,
                root_flag=root_flag,
                flags_validated=flags_validated,
                execution_time=execution_result['execution_time'],
                tools_used=execution_result.get('tools_used', []),
                discoveries=execution_result.get('discoveries', []),
                error=execution_result.get('error')
            )
            
            # Step 6: Record attempt
            self.selector.record_attempt(machine.id, success)
            
            # Step 7: Save session data
            self._save_session(session)
            
            # Step 8: Cleanup
            logger.info("Step 5: Cleaning up...")
            await self.htb_client.terminate_machine(machine.id)
            
            logger.info("="*60)
            if success:
                logger.info(f"✅ Session SUCCESS: {machine.name}")
                logger.info(f"   Flags validated: {flags_validated}")
                logger.info(f"   Time: {session.execution_time:.1f}s")
            else:
                logger.info(f"❌ Session FAILED: {machine.name}")
                if session.error:
                    logger.info(f"   Error: {session.error}")
            logger.info("="*60)
            
            return session
            
        except Exception as e:
            logger.error(f"Session failed: {e}")
            
            session = TrainingSession(
                session_id=session_id,
                machine=machine if 'machine' in locals() else HTBMachine(0, "unknown", "unknown", "unknown"),
                start_time=session_start,
                end_time=datetime.now(),
                status=SessionStatus.FAILED,
                error=str(e)
            )
            
            self._save_session(session)
            return session
    
    def _extract_flag(self, flags: List[str], flag_type: str) -> Optional[str]:
        """Extract user or root flag from list"""
        import re
        for flag in flags:
            if flag_type.lower() in flag.lower():
                # Extract hash (32 hex characters)
                match = re.search(r'[a-f0-9]{32}', flag)
                if match:
                    return match.group(0)
        return None
    
    def _save_session(self, session: TrainingSession):
        """Save session data to disk"""
        try:
            session_file = self.data_dir / f"{session.session_id}.json"
            with open(session_file, 'w') as f:
                json.dump({
                    'session_id': session.session_id,
                    'machine': {
                        'id': session.machine.id,
                        'name': session.machine.name,
                        'os': session.machine.os,
                        'difficulty': session.machine.difficulty,
                        'ip': session.machine.ip
                    },
                    'start_time': session.start_time.isoformat(),
                    'end_time': session.end_time.isoformat() if session.end_time else None,
                    'status': session.status.value,
                    'user_flag': session.user_flag,
                    'root_flag': session.root_flag,
                    'flags_validated': session.flags_validated,
                    'execution_time': session.execution_time,
                    'tools_used': session.tools_used,
                    'discoveries': session.discoveries,
                    'error': session.error
                }, f, indent=2)
            logger.info(f"Session data saved: {session_file}")
        except Exception as e:
            logger.error(f"Failed to save session: {e}")
    
    async def run_continuous(
        self,
        max_sessions: Optional[int] = None,
        delay_between_sessions: int = 300
    ):
        """
        Run continuous training loop
        
        Args:
            max_sessions: Maximum number of sessions (None = infinite)
            delay_between_sessions: Delay in seconds between sessions
        """
        session_count = 0
        
        while max_sessions is None or session_count < max_sessions:
            session_count += 1
            
            logger.info(f"\n{'='*60}")
            logger.info(f"Starting session {session_count}")
            logger.info(f"{'='*60}\n")
            
            session = await self.run_single_session()
            
            # Check if we should trigger retraining
            if session_count % 10 == 0:
                logger.info("\n🔄 Triggering model retraining...")
                # TODO: Trigger Axolotl training
            
            # Delay before next session
            if max_sessions is None or session_count < max_sessions:
                logger.info(f"\nWaiting {delay_between_sessions}s before next session...")
                await asyncio.sleep(delay_between_sessions)


async def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(description="HTB Training Runner")
    parser.add_argument('--sessions', type=int, help='Max sessions (default: infinite)')
    parser.add_argument('--delay', type=int, default=300, help='Delay between sessions (seconds)')
    parser.add_argument('--data-dir', type=str, default='training_data', help='Data directory')
    parser.add_argument('--huntress-root', type=str, default='.', help='Huntress root directory')
    
    args = parser.parse_args()
    
    # Get HTB API token from environment
    htb_api_token = os.getenv('HTB_API_TOKEN')
    if not htb_api_token:
        logger.error("HTB_API_TOKEN environment variable not set")
        sys.exit(1)
    
    # Create runner
    runner = HTBRunner(
        htb_api_token=htb_api_token,
        huntress_root=Path(args.huntress_root),
        data_dir=Path(args.data_dir)
    )
    
    # Run
    try:
        await runner.run_continuous(
            max_sessions=args.sessions,
            delay_between_sessions=args.delay
        )
    except KeyboardInterrupt:
        logger.info("\n\nShutdown requested by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())