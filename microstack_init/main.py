"""Microstack Init

Initialize the databases and configuration files of a microstack
install.

We structure our init in the form of 'Question' classes, each of which
has an 'ask' routine, run in the order laid out in the
question_classes in the main function in this file.

.ask will either ask the user a question, and run the appropriate
routine in the Question class, or simply automatically run a routine
without input from the user (in the case of 'required' questions).

----------------------------------------------------------------------

Copyright 2019 Canonical Ltd

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

"""

import argparse
import logging
import sys
import socket
import ipaddress

from functools import wraps

from microstack_init.config import log
from microstack_init.shell import (
    default_network,
    check,
    check_output,
    config_set,
    fallback_source_address,
)

from init import questions


def requires_sudo(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if int(check_output("id", "-u")):
            log.error(
                "This script must be run with root privileges. "
                "Please re-run with sudo."
            )
            sys.exit(1)

        return func(*args, **kwargs)

    return wrapper


def check_file_size_positive(value):
    ival = int(value)
    if ival < 1:
        raise argparse.ArgumentTypeError(
            f"The file size for a loop device"
            f" must be larger than 1GB, current: {value}"
        )
    return ival


def check_source_ip_address_valid(value):
    try:
        addr = ipaddress.ip_address(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(
            "Invalid source IP address provided in as an argument."
        ) from e
    return addr


def parse_init_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--auto", "-a", action="store_true", help="Run non interactively."
    )
    parser.add_argument(
        "--join",
        "-j",
        dest="connection_string",
        help="Pass a connection string generated by the"
        " add-compute command at the control node"
        " (required for compute nodes, unused for control"
        " nodes).",
    )
    parser.add_argument("--compute", action="store_true")
    parser.add_argument("--control", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument(
        "--setup-loop-based-cinder-lvm-backend",
        default=False,
        action="store_true",
        help="(experimental) set up a loop device-backed"
        " LVM backend for Cinder.",
    )
    parser.add_argument(
        "--loop-device-file-size",
        type=check_file_size_positive,
        default=32,
        help=(
            "File size in GB (10^9) of a file to be exposed as a loop"
            " device for the Cinder LVM backend."
        ),
    )
    parser.add_argument(
        "--default-source-ip",
        dest="default_source_ip",
        type=check_source_ip_address_valid,
        default=fallback_source_address(),
        help="The IP address to be used by MicroStack"
        " services as a source IP where possible. This"
        " option can be useful for multi-homed nodes.",
    )
    args = parser.parse_args()
    return args


def process_init_args(args):
    """Look through our args object and set the proper default config
    values in our snap config, based on those args.

    """
    if args.auto and not (args.control or args.compute):
        raise ValueError(
            "A role (--compute or --control) must be specified "
            " when using --auto"
        )

    if args.compute or args.control:
        config_set(**{"config.is-clustered": "true"})

    if args.compute:
        config_set(**{"config.cluster.role": "compute"})

    if args.control:
        # If both compute and control are passed for some reason, we
        # wind up with the role of 'control', which is best, as a
        # control node also serves as a compute node in our hyper
        # converged architecture.
        config_set(**{"config.cluster.role": "control"})

    if args.connection_string:
        config_set(
            **{"config.cluster.connection-string.raw": args.connection_string}
        )

    config_set(**{"config.network.default-source-ip": args.default_source_ip})

    if args.auto and not args.control and not args.connection_string:
        raise ValueError(
            "The connection string parameter must be specified"
            " for compute nodes."
        )

    if args.debug:
        log.setLevel(logging.DEBUG)

    config_set(
        **{
            "config.cinder.setup-loop-based-cinder-lvm-backend": f"{str(args.setup_loop_based_cinder_lvm_backend).lower()}",
            "config.cinder.loop-device-file-size": f"{args.loop_device_file_size}G",
        }
    )

    return args.auto


@requires_sudo
def init() -> None:
    args = parse_init_args()
    auto = process_init_args(args)

    # Do not ask about this if a CLI argument asking for it has been
    # provided already.
    cinder_lvm_question = questions.CinderVolumeLVMSetup()
    if args.setup_loop_based_cinder_lvm_backend:
        cinder_lvm_question.interactive = False

    question_list = [
        questions.DnsServers(),
        questions.DnsDomain(),
        questions.TlsCertificates(),
        questions.NetworkSettings(),
        questions.OsPassword(),  # TODO: turn this off if COMPUTE.
        # The following are not yet implemented:
        # questions.VmSwappiness(),
        # questions.FileHandleLimits(),
        questions.DashboardAccess(),
        questions.RabbitMq(),
        questions.DatabaseSetup(),
        questions.PlacementSetup(),
        questions.NovaControlPlane(),
        questions.NovaHypervisor(),
        questions.NovaSpiceConsoleSetup(),
        questions.NeutronControlPlane(),
        questions.GlanceSetup(),
        questions.SecurityRules(),
        questions.CinderSetup(),
        cinder_lvm_question,
        questions.PostSetup(),
        questions.ExtraServicesQuestion(),
    ]

    clustering_question = questions.Clustering()
    # If the connection string is specified we definitely
    # want to set up clustering and we don't need to ask.
    if args.connection_string:
        if args.auto:
            clustering_question.interactive = False
        if args.control:
            raise ValueError(
                "Joining additional control nodes is" " not supported."
            )
        elif args.compute:
            clustering_question.role_interactive = False
        config_set(**{"config.is-clustered": True})
        clustering_question.connection_string_interactive = False
        clustering_question.yes(answer=True)
    else:
        if args.control or args.compute:
            clustering_question.role_interactive = False
        # The same code-path as for other questions will be executed.
        question_list.insert(0, clustering_question)

    for question in question_list:
        if auto:
            # Force all questions to be non-interactive if we passed --auto.
            question.interactive = False

        try:
            question.ask()
        except questions.ConfigError as e:
            log.critical(e)
            sys.exit(1)


def set_network_info() -> None:
    """Find and use the  default network on a machine.

    Helper to find the default network on a machine, and configure
    MicroStack to use it in its default settings.

    """
    try:
        ip, gate, cidr = default_network()
    except Exception:
        # TODO: more specific exception handling.
        log.exception(
            "Could not determine default network info. "
            "Falling back on 10.20.20.1"
        )
        return

    check("snapctl", "set", "config.network.ext-gateway={}".format(gate))
    check("snapctl", "set", "config.network.ext-cidr={}".format(cidr))
    check("snapctl", "set", "config.network.control-ip={}".format(ip))
    check(
        "snapctl",
        "set",
        "config.network.node-fqdn={}".format(socket.getfqdn()),
    )


@requires_sudo
def remove() -> None:
    """Helper to cleanly uninstall MicroStack."""

    # Strip '--auto' out of the args passed to this command, as we
    # need to check it, but also pass the other args off to the
    # snapd's uninstall command. TODO: make this less hacky.
    auto = False
    if "--auto" in questions.uninstall.ARGS:
        auto = True
    questions.uninstall.ARGS = [
        arg for arg in questions.uninstall.ARGS if "auto" not in arg
    ]

    question_list = [
        questions.uninstall.DeleteBridge(),
        questions.uninstall.RemoveMicrostack(),
    ]

    for question in question_list:
        if auto:
            question.interactive = False
        question.ask()
