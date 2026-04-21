import argparse

from manyfaced.common.settings import HONEYPORT, HIVEPORT

"""
usage: mfh.py [-h] [-c [PORT]] [-s [PORT]] [-u] [-v]

Serve some sweet honey to the ubiquitous bots!

optional arguments:
  -h, --help     show this help message and exit
  -c [PORT]      port to start a CLIENT on
  -s [PORT]      port to start a SERVER on
  -u             enable self updating
  -v, --verbose  increase output verbosity

And that`s how you`d detect a sneaky bot.
"""


def parse():
    parser = argparse.ArgumentParser(
        description="Serve some sweet honey to the ubiquitous bots!",
        epilog="And that`s how you`d detect a sneaky chinese bot.",
        prog="mfh.py",
    )

    parser.add_argument(
        "-c",
        const=HONEYPORT,
        dest="client",
        help="port to start a CLIENT on",
        metavar="PORT",
        nargs="?",
        type=int,
    )

    parser.add_argument(
        "-s",
        const=HIVEPORT,
        dest="server",
        help="port to start a SERVER on",
        metavar="PORT",
        nargs="?",
        type=int,
    )

    parser.add_argument(
        "-u",
        action="store_true",
        dest="updater",
        help="enable self updating",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="increase output verbosity",
    )

    parser.add_argument(
        "-p",
        "--proxy",
        action="store_true",
        help="set this argument if you want to put honeypot behind proxy",
    )

    parser.add_argument(
        "--generate-config",
        action="store_true",
        dest="generate_config",
        default=False,
        help="generate a config.toml file at ~/.config/manyfaced/config.toml and exit",
    )
    
    # Port mode flags (for CLIENT mode)
    parser.add_argument(
        "--port-mode",
        choices=["single", "top", "all"],
        default="single",
        dest="port_mode",
        help="Port listening mode: 'single' (one port), 'top' (top 50 scanned ports), 'all' (all 65535 ports). Default: single",
    )
    parser.add_argument(
        "--top-ports",
        type=str,
        default="",
        dest="top_ports",
        help="Comma-separated list of ports to listen on when port-mode=top. Example: '80,443,8080,3306'",
    )

    # AI responder flags (for CLIENT mode)
    parser.add_argument(
        "--ai-responder",
        action="store_true",
        dest="ai_responder",
        default=False,
        help="Enable AI-powered interactive response generation for bot probes",
    )
    parser.add_argument(
        "--ai-endpoint",
        type=str,
        default="",
        dest="ai_endpoint",
        help="LLM API endpoint URL (OpenAI-compatible). Example: 'http://127.0.0.1:8080/v1'",
    )
    parser.add_argument(
        "--ai-model",
        type=str,
        default="",
        dest="ai_model",
        help="LLM model name. Example: 'llama-3.1-8b-instruct'",
    )
    parser.add_argument(
        "--ai-max-tokens",
        type=int,
        default=0,
        dest="ai_max_tokens",
        help="Maximum tokens in AI-generated response (default: 500)",
    )

    return parser.parse_args()
