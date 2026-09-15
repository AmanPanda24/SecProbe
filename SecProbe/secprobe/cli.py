"""
SecProbe - CLI Interface
Kali Linux terminal-based security scanner.
Author: Aman Kumar Panda 
"""

import click
import os
import json
from colorama import init, Fore, Style
from .scanner import SecProbe

init(autoreset=True)

BANNER = r"""
  ██████ ▓█████  ▄████▄   ██▓███   ██▀███   ▒█████   ▄▄▄▄   ▓█████ 
▒██    ▒ ▓█   ▀ ▒██▀ ▀█  ▓██░  ██▒▓██ ▒ ██▒▒██▒  ██▒▓█████▄ ▓█   ▀ 
░ ▓██▄   ▒███   ▒▓█    ▄ ▓██░ ██▓▒▓██ ░▄█ ▒▒██░  ██▒▒██▒ ▄██▒███   
  ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒▒██▄█▓▒ ▒▒██▀▀█▄  ▒██   ██░▒██░█▀  ▒▓█  ▄ 
▒██████▒▒░▒████▒▒ ▓███▀ ░▒██▒ ░  ░░██▓ ▒██▒░ ████▓▒░░▓█  ▀█▓░▒████▒
▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ░▒ ▒  ░▒▓▒░ ░  ░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ░▒▓███▀▒░░ ▒░ ░
░ ░▒  ░ ░ ░ ░  ░  ░  ▒   ░▒ ░       ░▒ ░ ▒░  ░ ▒ ▒░ ▒░▒   ░  ░ ░  ░
░  ░  ░     ░   ░        ░░         ░░   ░ ░ ░ ░ ▒   ░    ░    ░   
      ░     ░  ░░ ░                   ░         ░ ░   ░         ░  ░
"""

SEVERITY_COLORS = {
    "Critical": Fore.RED + Style.BRIGHT,
    "High":     Fore.RED,
    "Medium":   Fore.YELLOW,
    "Low":      Fore.CYAN,
    "Info":     Fore.WHITE,
}

GRADE_COLORS = {
    "A": Fore.GREEN + Style.BRIGHT,
    "B": Fore.GREEN,
    "C": Fore.YELLOW,
    "D": Fore.YELLOW + Style.BRIGHT,
    "F": Fore.RED + Style.BRIGHT,
}

PROVIDER_COLORS = {
    "gemini":  Fore.BLUE,
    "groq":    Fore.MAGENTA,
    "offline": Fore.WHITE,
}


def colorize(text, severity):
    return f"{SEVERITY_COLORS.get(severity, Fore.WHITE)}{text}{Style.RESET_ALL}"


def print_banner():
    click.echo(Fore.GREEN + BANNER + Style.RESET_ALL)
    click.echo(Fore.GREEN + "  Nikto-inspired Web Security Scanner" + Style.RESET_ALL)
    click.echo(Fore.GREEN + "  By: Aman Kumar Panda  |  Version 1.0.0" + Style.RESET_ALL)
    click.echo()


def print_ai_status(gemini_key, groq_key, use_ai):
    if not use_ai:
        click.echo(f"  {Fore.WHITE}AI Mode   : Disabled{Style.RESET_ALL}")
        return
    if gemini_key:
        click.echo(f"  {Fore.BLUE}AI Mode   : Google Gemini (Free){Style.RESET_ALL}")
    elif groq_key:
        click.echo(f"  {Fore.MAGENTA}AI Mode   : Groq LLaMA 3 (Free){Style.RESET_ALL}")
    else:
        click.echo(f"  {Fore.WHITE}AI Mode   : Offline Engine (No key needed){Style.RESET_ALL}")


def print_report(report, verbose=False):
    score = report["score"]
    grade = report["grade"]
    issues = report["issues"]
    summary = report["summary"]
    grade_color = GRADE_COLORS.get(grade, Fore.WHITE)

    click.echo(f"\n{Fore.CYAN}{'─' * 62}{Style.RESET_ALL}")
    click.echo(f"  Target  : {Fore.WHITE}{report['target']}{Style.RESET_ALL}")
    click.echo(f"  Score   : {grade_color}{score}/100  (Grade: {grade}){Style.RESET_ALL}")
    click.echo(f"  Issues  : {len(issues)} found  |  Scan time: {report['scan_time_seconds']}s")
    click.echo(
        f"  Summary : "
        f"{Fore.RED + Style.BRIGHT}Critical:{summary['critical']}  "
        f"{Fore.RED}High:{summary['high']}  "
        f"{Fore.YELLOW}Medium:{summary['medium']}  "
        f"{Fore.CYAN}Low:{summary['low']}  "
        f"{Fore.WHITE}Info:{summary['info']}{Style.RESET_ALL}"
    )
    click.echo(f"{Fore.CYAN}{'─' * 62}{Style.RESET_ALL}\n")

    if not issues:
        click.echo(Fore.GREEN + "  ✓ No issues found. Site looks secure!" + Style.RESET_ALL)
        return

    for i, issue in enumerate(issues, 1):
        sev = issue.get("severity", "Info")
        provider = issue.get("ai_provider", "")
        pcolor = PROVIDER_COLORS.get(provider, Fore.WHITE)
        provider_tag = f" {pcolor}[{provider}]{Style.RESET_ALL}" if provider else ""

        click.echo(f"  {i:02d}. {colorize(f'[{sev.upper()}]', sev)} {colorize(issue.get('type', ''), sev)}{provider_tag}")
        click.echo(f"      Category : {issue.get('category', 'General')}")

        if verbose:
            impact = issue.get("ai_impact") or issue.get("impact", "N/A")
            fix = issue.get("ai_fix") or issue.get("fix", "N/A")
            risk = issue.get("risk_score")
            click.echo(f"      Impact   : {impact}")
            click.echo(f"      Fix      :\n{Fore.GREEN}")
            for line in fix.split("\n"):
                click.echo(f"        {line}")
            click.echo(Style.RESET_ALL, nl=False)
            if risk is not None:
                click.echo(f"      Risk Score: {risk}/10.0")
            if issue.get("detail"):
                click.echo(f"      Detail   : {Fore.YELLOW}{issue['detail']}{Style.RESET_ALL}")
            if issue.get("reference"):
                click.echo(f"      Ref      : {Fore.BLUE}{issue['reference']}{Style.RESET_ALL}")
        else:
            fix = issue.get("ai_fix") or issue.get("fix", "N/A")
            first_line = fix.split("\n")[0]
            click.echo(f"      Fix: {Fore.GREEN}{first_line}{Style.RESET_ALL}")

        click.echo()

    click.echo(f"{Fore.CYAN}{'─' * 62}{Style.RESET_ALL}")


@click.command()
@click.argument("target")
@click.option("--ports", "-p", is_flag=True, default=False, help="Enable port scanning via nmap")
@click.option("--cve", is_flag=True, default=False,
              help="Check detected Server/X-Powered-By version banners against the NVD CVE database "
                   "(banner-based, best-effort — see README for accuracy caveats)")
@click.option("--nvd-key", envvar="NVD_API_KEY", default=None,
              help="Free NVD API key for higher rate limits (or set NVD_API_KEY env var). "
                   "Get one at https://nvd.nist.gov/developers/request-an-api-key")
@click.option("--ai", is_flag=True, default=False,
              help="Enable AI explanations (auto-picks Gemini/Groq/Offline)")
@click.option("--gemini-key", envvar="GEMINI_API_KEY", default=None,
              help="Google Gemini free API key (or set GEMINI_API_KEY env var)")
@click.option("--groq-key", envvar="GROQ_API_KEY", default=None,
              help="Groq free API key (or set GROQ_API_KEY env var)")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Show full details")
@click.option("--output", "-o", default=None, help="Save report to JSON file")
@click.option("--no-banner", is_flag=True, default=False, help="Suppress banner")
@click.option("--debug", is_flag=True, default=False,
              help="Print the raw fetched status code and headers before the report, to verify the scan actually hit this target")
@click.option("--no-discover", is_flag=True, default=False, help="Skip common-path/resource discovery checks")
@click.option("--timeout", default=10, show_default=True, type=int, help="HTTP request timeout in seconds")
def main(target, ports, cve, nvd_key, ai, gemini_key, groq_key, verbose, output, no_banner, debug, no_discover, timeout):
    """
    SecProbe - Nikto-inspired Web Security Scanner

    \b
    FREE AI Options (no paid key needed):
      Gemini: export GEMINI_API_KEY=your_key   (https://aistudio.google.com/app/apikey)
      Groq:   export GROQ_API_KEY=your_key     (https://console.groq.com/keys)
      Offline: secprobe example.com --ai        (no key needed at all!)

    \b
    Examples:
      secprobe example.com                            # Basic scan
      secprobe example.com --ai                       # AI offline mode (free, no key)
      secprobe example.com --ai --gemini-key KEY      # AI with Gemini (free)
      secprobe example.com --ai --groq-key KEY        # AI with Groq (free)
      secprobe example.com --ports --ai --verbose     # Full scan
      secprobe example.com --cve                      # Check version banners against NVD CVEs
      secprobe example.com --cve --nvd-key KEY        # CVE check with higher NVD rate limit
      secprobe example.com --output report.json       # Save report
      secprobe example.com --no-discover              # Fast header/TLS-only style scan
    """
    if not no_banner:
        print_banner()

    click.echo(f"  {Fore.CYAN}Scanning:{Style.RESET_ALL} {target}")
    print_ai_status(gemini_key, groq_key, ai)
    if ports:
        click.echo(f"  {Fore.YELLOW}Ports    : scanning enabled (may take longer)...{Style.RESET_ALL}")
    if cve:
        click.echo(f"  {Fore.YELLOW}CVE check: enabled — banner-based, best-effort (see README). "
                    f"May take longer due to NVD rate limits.{Style.RESET_ALL}")
    click.echo()

    try:
        scanner = SecProbe(
            target=target,
            scan_ports=ports,
            use_ai=ai,
            gemini_key=gemini_key,
            groq_key=groq_key,
            check_cve=cve,
            nvd_api_key=nvd_key,
            discover=not no_discover,
            timeout=timeout,
        )
        report = scanner.run()

        if debug:
            d = report.get("debug", {})
            click.echo(f"  {Fore.MAGENTA}── DEBUG FINGERPRINT ──{Style.RESET_ALL}")
            click.echo(f"  Requested target : {d.get('requested_target')}")
            click.echo(f"  Resolved host    : {d.get('resolved_hostname')}")
            click.echo(f"  Final URL        : {d.get('final_url_after_redirects')}")
            click.echo(f"  Status code      : {d.get('status_code')}")
            click.echo(f"  Used HTTPS       : {d.get('used_https')}")
            if d.get("redirect_chain"):
                click.echo(f"  Redirect chain   : {' -> '.join(d.get('redirect_chain'))}")
            if d.get("connection_attempts"):
                click.echo(f"  {Fore.YELLOW}Connection attempts:{Style.RESET_ALL}")
                for attempt in d.get("connection_attempts"):
                    click.echo(f"    {attempt}")
            click.echo(f"  Raw headers      :")
            for k, v in d.get("raw_headers", {}).items():
                click.echo(f"    {k}: {v}")
            click.echo()

        print_report(report, verbose=verbose)

        if output:
            with open(output, "w") as f:
                json.dump(report, f, indent=2)
            click.echo(f"\n  {Fore.GREEN}✓ Report saved: {output}{Style.RESET_ALL}\n")

    except KeyboardInterrupt:
        click.echo(Fore.YELLOW + "\n  Scan interrupted." + Style.RESET_ALL)
    except Exception as e:
        click.echo(Fore.RED + f"\n  Error: {e}" + Style.RESET_ALL)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
