"""
Pentest Toolbox - Docker Manager
Handles Exegol container lifecycle for scan execution
"""
import docker
import threading
import time
from typing import Optional, Callable


class DockerManager:
    """Manages Exegol Docker containers for running pentest tools"""
    
    def __init__(self, image: str = "nwodtuhs/exegol-full:latest"):
        self.image = image
        self.client = None
        self._containers = {}  # scan_id -> container
        
    def connect(self) -> bool:
        """Connect to Docker daemon"""
        try:
            self.client = docker.from_env()
            self.client.ping()
            return True
        except Exception as e:
            print(f"[!] Docker connection failed: {e}")
            return False
    
    def is_connected(self) -> bool:
        """Check if connected to Docker"""
        if not self.client:
            return False
        try:
            self.client.ping()
            return True
        except:
            return False
    
    def image_exists(self) -> bool:
        """Check if Exegol image is available locally"""
        if not self.client:
            return False
        try:
            self.client.images.get(self.image)
            return True
        except docker.errors.ImageNotFound:
            return False
    
    def get_or_create_container(self, scan_id: int, name_prefix: str = "pentest-scan") -> Optional[str]:
        """
        Get existing or create new Exegol container for a scan.
        Returns container ID or None on failure.
        """
        if not self.connect():
            return None
        
        container_name = f"{name_prefix}-{scan_id}"
        
        # Check if container already exists
        try:
            container = self.client.containers.get(container_name)
            if container.status != 'running':
                container.start()
            self._containers[scan_id] = container
            return container.id
        except docker.errors.NotFound:
            pass
        
        # Create new container
        try:
            container = self.client.containers.run(
                self.image,
                name=container_name,
                detach=True,
                tty=True,
                stdin_open=True,
                remove=False,  # We'll remove manually after scan
                network_mode="host",  # Allow scanning network targets
                mem_limit="2g",
                command="/bin/bash"
            )
            self._containers[scan_id] = container
            # Wait a moment for container to be fully ready
            time.sleep(1)
            return container.id
        except Exception as e:
            print(f"[!] Container creation failed: {e}")
            return None
    
    def exec_command(
        self, 
        scan_id: int, 
        command: str, 
        on_output: Optional[Callable[[str], None]] = None,
        timeout: int = 300
    ) -> tuple[int, str]:
        """
        Execute a command inside the container.
        
        Args:
            scan_id: The scan ID to identify the container
            command: Command to execute
            on_output: Callback for streaming output (line by line)
            timeout: Timeout in seconds
            
        Returns:
            Tuple of (exit_code, full_output)
        """
        container = self._containers.get(scan_id)
        if not container:
            return (-1, "[!] Container not found")
        
        try:
            # Refresh container state
            container.reload()
            if container.status != 'running':
                container.start()
                time.sleep(0.5)
            
            # Execute command
            exec_result = container.exec_run(
                cmd=f"/bin/bash -c '{command}'",
                stream=True,
                demux=True
            )
            
            full_output = []
            start_time = time.time()
            
            for stdout, stderr in exec_result.output:
                # Check timeout
                if time.time() - start_time > timeout:
                    full_output.append("\n[!] Command timeout\n")
                    break
                
                output = ""
                if stdout:
                    output += stdout.decode('utf-8', errors='replace')
                if stderr:
                    output += stderr.decode('utf-8', errors='replace')
                
                if output:
                    full_output.append(output)
                    if on_output:
                        on_output(output)
            
            return (0, ''.join(full_output))
            
        except Exception as e:
            return (-1, f"[!] Execution error: {e}")
    
    def cleanup_container(self, scan_id: int, force: bool = True) -> bool:
        """Remove container after scan completion"""
        container = self._containers.get(scan_id)
        if not container:
            return True
        
        try:
            container.reload()
            container.stop(timeout=5)
            container.remove(force=force)
            del self._containers[scan_id]
            return True
        except Exception as e:
            print(f"[!] Cleanup failed: {e}")
            return False
    
    def get_container_status(self, scan_id: int) -> Optional[str]:
        """Get container status (running, exited, etc.)"""
        container = self._containers.get(scan_id)
        if not container:
            return None
        try:
            container.reload()
            return container.status
        except:
            return None
    
    def list_available_tools(self, scan_id: int) -> list[str]:
        """List commonly used tools available in the container"""
        # These are known to be in exegol-full
        return [
            "nmap", "nikto", "sqlmap", "gobuster", "dirb",
            "hydra", "metasploit", "burpsuite", "zaproxy",
            "nuclei", "ffuf", "wfuzz", "whatweb", "sublist3r"
        ]


# Singleton instance
_docker_manager: Optional[DockerManager] = None


def get_docker_manager(image: str = "nwodtuhs/exegol-full:latest") -> DockerManager:
    """Get or create the Docker manager singleton"""
    global _docker_manager
    if _docker_manager is None:
        _docker_manager = DockerManager(image)
    return _docker_manager
