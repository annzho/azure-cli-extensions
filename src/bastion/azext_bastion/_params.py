# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
#
# Code generated by aaz-dev-tools
# --------------------------------------------------------------------------------------------

# pylint: disable=too-many-lines
# pylint: disable=too-many-statements

from azure.cli.core.commands.parameters import get_resource_name_completion_list, get_three_state_flag
from knack.arguments import CLIArgumentType


def load_arguments(self, _):  # pylint: disable=unused-argument
    bastion_host_name_type = CLIArgumentType(
        help="Name of the bastion host.",
        options_list="--bastion-host-name",
        completer=get_resource_name_completion_list("Microsoft.Network/bastionHosts"),
        id_part="name"
    )

    with self.argument_context("network bastion") as c:
        c.argument("bastion_host_name", bastion_host_name_type, options_list=["--name", "-n"])
        c.argument("resource_port", help="Resource port of the target VM to which the bastion will connect.",
                   options_list=["--resource-port"])
        c.argument("target_resource_id", help="ResourceId of the target Virtual Machine.",
                   options_list=["--target-resource-id"])

    with self.argument_context("network bastion ssh") as c:
        c.argument("auth_type", help="Auth type to use for SSH connections.", options_list=["--auth-type"])
        c.argument("ssh_key", help="SSH key file location for SSH connections.", options_list=["--ssh-key"])
        c.argument("username", help="User name for SSH connections.", options_list=["--username"])
    with self.argument_context("network bastion rdp") as c:
        c.argument("configure", help="Flag to configure RDP session.", action="store_true")
        c.argument("disable_gateway", help="Flag to disable access through RD gateway.",
                   arg_type=get_three_state_flag())
        c.argument('enable_mfa', help='Enable RDS auth for MFA if supported by the target machine.',
                   arg_type=get_three_state_flag())
    with self.argument_context("network bastion tunnel") as c:
        c.argument("port", help="Local port to use for the tunneling.", options_list=["--port"])
        c.argument("timeout", help="Timeout for connection to bastion host tunnel.", options_list=["--timeout"])
