import psutil
import datetime
import json
import os
import platform
import subprocess
import requests
import time
import logging
import configparser

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Helper functions
def format_bytes_to_gb(bytes_value):
    """Format bytes to gigabytes with 2 decimal places."""
    return f"{bytes_value / (1024**3):.2f} GB"

def format_percentage(value):
    """Format a float value as percentage string."""
    return f"{value}%"

def format_timestamp(timestamp):
    """Format a timestamp to ISO format string."""
    return datetime.datetime.fromtimestamp(timestamp).isoformat()

def extract_jvm_name(proc, p_info):
    """Extract a descriptive name for JVM processes."""
    descriptive_name = p_info['name']  # Fallback to 'java'
    try:
        cmdline = proc.cmdline()
        # Try to find the -jar argument
        if '-jar' in cmdline:
            jar_index = cmdline.index('-jar') + 1
            if jar_index < len(cmdline):
                # Use the basename of the JAR file
                descriptive_name = os.path.basename(cmdline[jar_index])
        else:
            # If no -jar, find the last argument that isn't an option (like a main class)
            for arg in reversed(cmdline):
                if not arg.startswith('-') and 'java' not in os.path.basename(arg):
                    descriptive_name = arg
                    break
    except (psutil.Error, IndexError):
        # Keep the default name if cmdline is inaccessible or parsing fails
        pass
    return descriptive_name

def get_disk_usage():
    """Collects disk usage data for each volume, including inode usage."""
    partitions = psutil.disk_partitions()
    disk_usage_data = {}
    for partition in partitions:
        if os.path.exists(partition.mountpoint):
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_data = {
                    "mountpoint": partition.mountpoint,
                    "total": format_bytes_to_gb(usage.total),
                    "used": format_bytes_to_gb(usage.used),
                    "free": format_bytes_to_gb(usage.free),
                    "percent_used": format_percentage(usage.percent)
                }
                # Inode usage (Unix-specific)
                try:
                    inodes = os.statvfs(partition.mountpoint)
                    inodes_total = inodes.f_files
                    inodes_free = inodes.f_ffree
                    inodes_used = inodes_total - inodes_free
                    inodes_percent_used = 0
                    if inodes_total > 0:
                        inodes_percent_used = round((inodes_used / inodes_total) * 100, 2)

                    disk_data['inodes_total'] = inodes_total
                    disk_data['inodes_used'] = inodes_used
                    disk_data['inodes_free'] = inodes_free
                    disk_data['inodes_percent_used'] = inodes_percent_used
                except (AttributeError, OSError):
                    disk_data['inodes_total'] = None
                    disk_data['inodes_used'] = None
                    disk_data['inodes_free'] = None
                    disk_data['inodes_percent_used'] = None
                
                disk_usage_data[partition.device] = disk_data
            except (FileNotFoundError, PermissionError):
                pass
            
    return disk_usage_data

def get_disk_iops():
    """Collects disk IOPS (Input/Output Operations Per Second) data with real-time calculation."""
    try:
        # Take first snapshot
        first_snapshot = psutil.disk_io_counters(perdisk=True)
        if not first_snapshot:
            return {}
        
        first_time = time.time()
        
        # Wait 1 second to get accurate data
        time.sleep(1)
        
        # Take second snapshot
        second_snapshot = psutil.disk_io_counters(perdisk=True)
        second_time = time.time()
        
        time_delta = second_time - first_time
        if time_delta == 0:
            time_delta = 1  # Avoid division by zero
        
        iops_data = {}
        for disk, current_stats in second_snapshot.items():
            last_stats = first_snapshot.get(disk)
            if not last_stats:
                continue
                
            # Calculate IOPS and throughput rates
            read_iops = (current_stats.read_count - last_stats.read_count) / time_delta
            write_iops = (current_stats.write_count - last_stats.write_count) / time_delta
            read_mb_s = ((current_stats.read_bytes - last_stats.read_bytes) / time_delta) / (1024 * 1024)
            write_mb_s = ((current_stats.write_bytes - last_stats.write_bytes) / time_delta) / (1024 * 1024)
            
            iops_data[disk] = {
                'read_iops': round(read_iops, 1),
                'write_iops': round(write_iops, 1),
                'read_mb_s': round(read_mb_s, 1),
                'write_mb_s': round(write_mb_s, 1),
                'read_count': current_stats.read_count,
                'write_count': current_stats.write_count,
                'read_bytes': current_stats.read_bytes,
                'write_bytes': current_stats.write_bytes,
                'read_time': current_stats.read_time,
                'write_time': current_stats.write_time,
                'read_merged_count': current_stats.read_merged_count,
                'write_merged_count': current_stats.write_merged_count,
                'busy_time': current_stats.busy_time
            }
        return iops_data
    except (PermissionError, RuntimeError):
        return {}

def get_memory_utilization():
    """Collects memory utilization data."""
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return {
        "virtual_memory": {
            "total": format_bytes_to_gb(memory.total),
            "available": format_bytes_to_gb(memory.available),
            "percent_used": format_percentage(memory.percent),
            "used": format_bytes_to_gb(memory.used),
            "free": format_bytes_to_gb(memory.free)
        },
        "swap_memory": {
            "total": format_bytes_to_gb(swap.total),
            "used": format_bytes_to_gb(swap.used),
            "free": format_bytes_to_gb(swap.free),
            "percent_used": format_percentage(swap.percent)
        }
    }

def get_system_info():
    """Collects basic system information."""
    uname = platform.uname()
    return {
        "system": uname.system,
        "node_name": uname.node,
        "release": uname.release,
        "version": uname.version,
        "machine": uname.machine,
        "processor": uname.processor,
    }

def get_logged_in_users():
    """Gets a list of currently logged-in users."""
    try:
        users = psutil.users()
        return [{"name": user.name, "terminal": user.terminal, "host": user.host, "started": format_timestamp(user.started), "pid": getattr(user, 'pid', None)} for user in users]
    except (AttributeError, NotImplementedError):
        return "Not available on this OS"

def get_sensor_data():
    """Collects sensor data like temperatures and fan speeds."""
    sensor_data = {}
    # Temperatures
    try:
        temps = psutil.sensors_temperatures()
        if temps:
            sensor_data['temperatures'] = {}
            for name, entries in temps.items():
                sensor_data['temperatures'][name] = [entry._asdict() for entry in entries]
        else:
            sensor_data['temperatures'] = "Not available or no sensors found"
    except (AttributeError, NotImplementedError):
        sensor_data['temperatures'] = "Not supported on this OS"

    # Fan speeds
    try:
        fans = psutil.sensors_fans()
        if fans:
            sensor_data['fans'] = {}
            for name, entries in fans.items():
                sensor_data['fans'][name] = [entry._asdict() for entry in entries]
        else:
            sensor_data['fans'] = "Not available or no sensors found"
    except (AttributeError, NotImplementedError):
        sensor_data['fans'] = "Not supported on this OS"
    
    return sensor_data

def get_system_uptime():
    """Gets system boot time and uptime."""
    boot_time_timestamp = psutil.boot_time()
    boot_time = datetime.datetime.fromtimestamp(boot_time_timestamp)
    uptime = datetime.datetime.now() - boot_time
    return {
        "boot_time": boot_time.isoformat(),
        "uptime_seconds": uptime.total_seconds(),
        "uptime_days": uptime.days,
        "uptime_hours": uptime.seconds // 3600,
        "uptime_minutes": (uptime.seconds % 3600) // 60
    }

def get_cpu_utilization():
    """Collects CPU utilization data with time consistency for overall and per-CPU."""
    cpu_freq = None
    try:
        cpu_freq = psutil.cpu_freq()
    except (AttributeError, NotImplementedError, PermissionError):
        pass

    # Get per-CPU percent first with interval for accurate data
    per_cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
    
    # Calculate overall percent from average of per-CPU for consistency
    overall_percent = sum(per_cpu_percent) / len(per_cpu_percent) if per_cpu_percent else 0.0

    return {
        "overall_percent": round(overall_percent, 1),
        "per_cpu_percent": [round(cpu, 1) for cpu in per_cpu_percent],
        "cpu_count_logical": psutil.cpu_count(logical=True),
        "cpu_count_physical": psutil.cpu_count(logical=False),
        "cpu_times_percent": psutil.cpu_times_percent()._asdict(),
        "cpu_frequency": {
            "current": cpu_freq.current,
            "min": cpu_freq.min,
            "max": cpu_freq.max
        } if cpu_freq else "Not available"
    }

def get_system_load():
    """Collects system load average (Unix-specific)."""
    try:
        load_avg = psutil.getloadavg()
        return {
            "load_avg_1min": load_avg[0],
            "load_avg_5min": load_avg[1],
            "load_avg_15min": load_avg[2]
        }
    except (AttributeError, OSError):
        return "Not available on this OS"

def get_network_info():
    """Collects network information."""
    connections = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                connections.append({
                    "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}",
                    "pid": conn.pid
                })
    except psutil.AccessDenied:
        connections = "Access Denied"

    interfaces = {}
    try:
        for name, addrs in psutil.net_if_addrs().items():
            interfaces[name] = []
            for addr in addrs:
                interfaces[name].append({
                    "family": addr.family.name,
                    "address": addr.address,
                    "netmask": addr.netmask,
                })
    except (AttributeError, NotImplementedError):
        interfaces = "Not available on this OS"

    network_stats = {}
    try:
        net_io = psutil.net_io_counters(pernic=True)
        network_stats = {interface: stats._asdict() for interface, stats in net_io.items()}
    except (AttributeError, NotImplementedError):
        network_stats = "Not available on this OS"

    return {
        "established_connections": connections,
        "interface_addresses": interfaces,
        "interface_stats": network_stats
    }

def get_listening_ports():
    """Gets all listening ports and the processes associated with them."""
    listening_ports = []
    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.status == psutil.CONN_LISTEN:
                proc_name = "N/A"
                try:
                    if conn.pid:
                        proc_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = "Access Denied"
                
                listening_ports.append({
                    "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "pid": conn.pid,
                    "process_name": proc_name
                })
        return listening_ports
    except psutil.AccessDenied:
        return "Access Denied to network connections."
    except Exception as e:
        return f"An error occurred: {str(e)}"

def get_top_processes(top_n=10):
    """Gets top processes by CPU and memory usage with interval for accurate CPU."""
    all_processes = []
    jvm_processes = []
    status_counts = {'running': 0, 'sleeping': 0, 'stopped': 0, 'zombie': 0, 'other': 0, 'total': 0}
    
    # First pass: collect all processes and get first CPU reading
    processes = list(psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'memory_info', 'status', 'create_time', 'num_threads']))
    
    # Get initial CPU percent for all processes (will be 0.0 on first call)
    for proc in processes:
        try:
            proc.cpu_percent()  # Initialize CPU measurement
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    
    # Wait for interval to get accurate CPU readings
    logger.info("Waiting 1 second for accurate CPU usage calculation...")
    time.sleep(1)
    
    # Second pass: get accurate CPU percent and collect data
    for proc in processes:
        try:
            # Get process info
            p_info = proc.info
            status = p_info.get('status')
            if status in status_counts:
                status_counts[status] += 1
            else:
                status_counts['other'] += 1
            status_counts['total'] += 1

            # Get accurate CPU percent with interval
            try:
                cpu_percent = proc.cpu_percent()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                cpu_percent = 0.0
            
            p_info['cpu_percent'] = cpu_percent

            if p_info.get('create_time'):
                p_info['create_time'] = format_timestamp(p_info['create_time'])
            
            # Check for JVM processes before modifying p_info
            if 'java' in (p_info.get('name') or '').lower():
                descriptive_name = extract_jvm_name(proc, p_info)
                jvm_processes.append({
                    "pid": p_info['pid'],
                    "name": descriptive_name,
                    "user": p_info['username'],
                    "cpu_percent": cpu_percent,
                    "memory_rss": f"{p_info['memory_info'].rss / (1024**2):.2f} MB"
                })
            
            # Remove memory_info from general process info as it's handled separately
            p_info.pop('memory_info', None)
            all_processes.append(p_info)
                
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Sort processes
    top_cpu = sorted(all_processes, key=lambda p: p.get('cpu_percent') or 0, reverse=True)[:top_n]
    top_memory = sorted(all_processes, key=lambda p: p.get('memory_percent') or 0, reverse=True)[:top_n]

    return {
        "process_summary": status_counts,
        "jvm_utilization": jvm_processes,
        "top_processes": {
            f"top_{top_n}_by_cpu": top_cpu,
            f"top_{top_n}_by_memory": top_memory
        }
    }

def get_docker_info():
    """Collects information about running and stopped Docker containers."""
    if platform.system() != "Linux":
        return "Docker info is currently only supported on Linux."
    try:
        subprocess.check_output(['which', 'docker'])
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "Docker command not found."

    try:
        cmd = ["docker", "ps", "--all", "--format", "{{json .}}"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=10)

        if result.returncode != 0:
            return f"Error running Docker command: {result.stderr.strip()}"

        if not result.stdout.strip():
            return []

        containers = []
        for line in result.stdout.strip().split('\n'):
            if line:
                containers.append(json.loads(line))
        return containers
    except subprocess.TimeoutExpired:
        return "Docker command timed out."
    except Exception as e:
        return f"Error fetching Docker info: {str(e)}"

def get_systemd_services_status():
    """Checks the status of specified systemd services."""
    if platform.system() != "Linux":
        return "systemd is only available on Linux."
        
    services_to_check = ['sshd', 'httpd', 'nginx', 'mysql', 'mariadb', 'postgresql', 'docker', 'firewalld', 'cron', 'systemd-journald']
    statuses = {}
    
    try:
        systemctl_path = subprocess.check_output(['which', 'systemctl']).strip().decode()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "systemctl command not found."

    for service in services_to_check:
        try:
            cmd = [systemctl_path, 'show', service, '--property=LoadState', '--property=ActiveState', '--property=SubState']
            result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=5)

            if result.returncode == 0 and result.stdout:
                service_info = {}
                for line in result.stdout.strip().split('\n'):
                    key, value = line.split('=', 1)
                    service_info[key] = value
                
                if service_info.get('LoadState') != 'not-found':
                    statuses[service] = {
                        'load_state': service_info.get('LoadState', 'unknown'),
                        'active_state': service_info.get('ActiveState', 'unknown'),
                        'sub_state': service_info.get('SubState', 'unknown'),
                    }
        except (subprocess.TimeoutExpired, Exception):
            pass
            
    return statuses

def get_firewall_rules():
    """Collects firewall rules from firewalld or iptables."""
    rules = {}
    try:
        # Prefer firewalld on modern systems
        subprocess.check_output(['which', 'firewall-cmd'])
        cmd = ["firewall-cmd", "--list-all"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=10)
        if result.returncode == 0:
            rules['firewalld'] = result.stdout.strip()
        else:
            rules['firewalld_error'] = result.stderr.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        # Fallback to iptables
        try:
            subprocess.check_output(['which', 'iptables'])
            cmd = ["iptables", "-L", "-n", "-v"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=10)
            if result.returncode == 0:
                rules['iptables'] = result.stdout.strip()
            else:
                rules['iptables_error'] = result.stderr.strip()
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return "No firewall command (firewall-cmd or iptables) found or command timed out."
    except Exception as e:
        return f"An error occurred while fetching firewall rules: {str(e)}"
    return rules

def get_cron_jobs():
    """Lists cron jobs for common users (current user and root)."""
    cron_data = {}
    # Use a set to avoid duplicates if the script is run as root
    users_to_check = set()
    try:
        users_to_check.add(os.getlogin())
    except OSError: # os.getlogin() can fail in some environments (e.g. cron)
        pass
    users_to_check.add('root')

    for user in users_to_check:
        cron_path = f"/var/spool/cron/{user}"
        if os.path.exists(cron_path):
            try:
                with open(cron_path, 'r') as f:
                    jobs = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
                    cron_data[user] = jobs
            except PermissionError:
                cron_data[user] = "Permission denied to read crontab."
            except Exception as e:
                cron_data[user] = f"Error reading crontab: {str(e)}"
        else:
            cron_data[user] = "No crontab found."
            
    return cron_data

def collect_all_data():
    """Collects all system data in one function."""
    logger.info("📊 Starting system data collection...")
    
    report_data = {}
    
    # Collect all data according to the order in newest-report.json
    logger.info("Collecting memory data...")
    report_data["memory_utilization"] = get_memory_utilization()
    
    logger.info("Collecting system load average...")
    report_data["system_load_average"] = get_system_load()
    
    logger.info("Collecting disk IOPS data...")
    report_data["disk_iops"] = get_disk_iops()
    
    logger.info("Collecting system uptime...")
    report_data["system_uptime"] = get_system_uptime()
    
    logger.info("Collecting disk usage data...")
    report_data["disk_usage_per_volume"] = get_disk_usage()
    
    logger.info("Collecting cron jobs...")
    report_data["cron_jobs"] = get_cron_jobs()
    
    logger.info("Collecting sensor data...")
    report_data["sensor_data"] = get_sensor_data()
    
    logger.info("Collecting logged in users...")
    report_data["logged_in_users"] = get_logged_in_users()
    
    logger.info("Collecting system information...")
    report_data["system_information"] = get_system_info()
    
    logger.info("Collecting network data...")
    report_data["network_info"] = get_network_info()
    
    logger.info("Collecting listening ports...")
    report_data["listening_ports"] = get_listening_ports()
    
    logger.info("Collecting Docker containers...")
    report_data["docker_containers"] = get_docker_info()
    
    logger.info("Collecting process data...")
    process_data = get_top_processes()
    report_data["jvm_utilization"] = process_data["jvm_utilization"]
    report_data["process_summary"] = process_data["process_summary"]
    
    logger.info("Collecting systemd services...")
    report_data["systemd_services"] = get_systemd_services_status()
    
    report_data["top_processes"] = process_data["top_processes"]
    
    logger.info("Collecting firewall rules...")
    report_data["firewall_rules"] = get_firewall_rules()
    
    logger.info("Collecting CPU data...")
    report_data["cpu_utilization"] = get_cpu_utilization()
    
    # Add metadata at the end according to original order
    report_data["report_generated_at"] = datetime.datetime.now().isoformat()
    report_data["server_hostname"] = platform.node()
    
    logger.info("✅ All data successfully collected!")
    return report_data

def send_data_to_api(data, endpoint_url, timeout=30, user_agent='ServerMonitor/1.0'):
    """Sends JSON data to REST API endpoint."""
    try:
        logger.info(f"📤 Sending data to API: {endpoint_url}")
        
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': user_agent
        }
        
        response = requests.post(
            endpoint_url,
            json=data,
            headers=headers,
            timeout=timeout
        )
        
        response.raise_for_status()
        
        logger.info(f"✅ Data sent successfully! Status: {response.status_code}")
        logger.info(f"Response: {response.text[:200]}...")  # Show first 200 chars
        
        return True
        
    except requests.exceptions.RequestException as e:
        logger.error(f"❌ Failed to send data to API: {e}")
        return False
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}")
        return False

def save_local_backup(data, filename="server-report-backup.json"):
    """Saves local backup of the data."""
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(script_dir, filename)
        
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"💾 Local backup saved at: {file_path}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to save local backup: {e}")
        return False

def load_config(config_file="config.ini"):
    """Loads configuration from .ini file"""
    config = configparser.ConfigParser()
    
    # Default values
    default_config = {
        'API': {
            'endpoint': 'https://example.com/api/server-reports',
            'timeout': '30',
            'user_agent': 'ServerMonitor/1.0'
        },
        'GENERAL': {
            'backup_enabled': 'false',
            'backup_filename': 'server-report-backup.json',
            'log_level': 'INFO'
        }
    }
    
    # Check if config file exists
    if not os.path.exists(config_file):
        logger.info(f"📝 Configuration file {config_file} not found, creating default file...")
        create_default_config(config_file, default_config)
    
    try:
        config.read(config_file)
        logger.info(f"✅ Configuration successfully loaded from {config_file}")
        return config
    except Exception as e:
        logger.error(f"❌ Failed to read configuration file: {e}")
        logger.info("Using default configuration...")
        config.read_dict(default_config)
        return config

def create_default_config(config_file, default_config):
    """Creates default configuration file"""
    config = configparser.ConfigParser()
    config.read_dict(default_config)
    
    try:
        with open(config_file, 'w') as f:
            # Write header comments
            f.write("# Server Monitor Configuration File\n")
            f.write("# Please edit this file according to your needs\n\n")
            config.write(f)
        logger.info(f"✅ Default configuration file successfully created: {config_file}")
    except Exception as e:
        logger.error(f"❌ Failed to create configuration file: {e}")

def main():
    """Main function that runs the program."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Server Monitoring - Simple Version')
    parser.add_argument('--config', type=str, default='config.ini',
                       help='Path to .ini configuration file (default: config.ini)')
    
    args = parser.parse_args()
    
    try:
        logger.info("🚀 Starting Server Monitor...")
        
        # Load configuration
        config = load_config(args.config)
        
        # Set log level from config
        log_level = config.get('GENERAL', 'log_level', fallback='INFO')
        logging.getLogger().setLevel(getattr(logging, log_level.upper()))
        
        # Get API configuration
        api_endpoint = config.get('API', 'endpoint')
        api_timeout = config.getint('API', 'timeout', fallback=30)
        user_agent = config.get('API', 'user_agent', fallback='ServerMonitor/1.0')
        
        # Get backup configuration
        backup_enabled = config.getboolean('GENERAL', 'backup_enabled', fallback=False)
        backup_filename = config.get('GENERAL', 'backup_filename', fallback='server-report-backup.json')
        
        logger.info(f"📡 API Endpoint: {api_endpoint}")
        logger.info(f"� Backup: {'Enabled' if backup_enabled else 'Disabled'}")
        
        # Collect all data
        data = collect_all_data()
        
        # Save local backup if requested
        if backup_enabled:
            save_local_backup(data, backup_filename)
        
        # Send to API
        success = send_data_to_api(data, api_endpoint, api_timeout, user_agent)
        
        if success:
            logger.info("🎉 Program completed successfully!")
            return 0
        else:
            logger.error("💥 Program completed with error!")
            return 1
            
    except KeyboardInterrupt:
        logger.info("⏹️ Program stopped by user")
        return 0
    except Exception as e:
        logger.error(f"💥 Fatal error: {e}")
        return 1

if __name__ == "__main__":
    exit(main())