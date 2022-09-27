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

import sys

from microstack_init.config import Env, log
from microstack_init.questions.question import Question
from microstack_init.shell import call

_env = Env().get_env()


# Save off command line args. If you use any of these to answer a
# question, pop it from this list -- the remaining args will get
# passed to "snap remove"
ARGS = list(sys.argv)


class DeleteBridge(Question):
    _type = "boolean"
    _question = "Do you wish to delete the ovs bridge? (br-ex)"
    interactive = True
    config_key = "config.cleanup.delete-bridge"

    def yes(self, answer):
        log.info("Removing ovs bridge.")
        # Remove bridge. This may not exist, so we silently skip on error.
        # TODO get bridge name from config (if it gets added to config)
        # TODO clean up other ovs artifacts?
        call("ovs-vsctl", "del-br", "br-ex")


# TODO: cleanup system optimizations
# TODO: cleanup kernel modules?


class RemoveMicrostack(Question):
    _type = "auto"
    _question = "Do you really wish to remove MicroStack?"
    interactive = True
    config_key = "config.cleanup.remove"

    def yes(self, answer):
        """Uninstall MicroStack, passing any command line options to snapd."""
        log.info("Uninstalling MicroStack (this may take a while) ...")
