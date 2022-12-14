# Copyright 2022 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from microstack_init.config import Env, log
from microstack_init.questions.question import Question
from microstack_init.shell import (
    check,
    config_get,
    config_set,
)

_env = Env().get_env()


class ExtGateway(Question):
    """Possibly override default ext gateway."""

    _type = "string"
    _question = "External Gateway"
    config_key = "config.network.ext-gateway"

    def yes(self, answer):
        clustered = config_get("config.is-clustered")
        if not clustered:
            ip_dict = {
                "config.network.control-ip": answer,
                "config.network.compute-ip": answer,
            }
            config_set(**ip_dict)
            _env.update(ip_dict)
        else:
            ip_dict = config_get(
                *["config.network.control-ip", "config.network.compute-ip"]
            )
            _env.update(
                {
                    "control_ip": ip_dict["config.network.control-ip"],
                    "compute_ip": ip_dict["config.network.compute-ip"],
                }
            )


class ExtCidr(Question):
    """Possibly override the cidr."""

    _type = "string"
    _question = "External Ip Range"
    config_key = "config.network.ext-cidr"

    def yes(self, answer):
        _env["extcidr"] = answer


class IpForwarding(Question):
    """Possibly setup IP forwarding."""

    _type = "boolean"  # Auto for now, to maintain old behavior.
    _question = "Do you wish to setup ip forwarding? (recommended)"
    config_key = "config.host.ip-forwarding"

    def yes(self, answer: str) -> None:
        """Use sysctl to setup ip forwarding."""
        log.info("Setting up ipv4 forwarding...")

        check("sysctl", "net.ipv4.ip_forward=1")

    def no(self, answer: str) -> None:
        """This question doesn't actually work in a strictly confined snap, so
        we default to the no and a noop for now.

        """
        pass
