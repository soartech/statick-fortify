"""Apply Fortify tool and gather results."""

from __future__ import print_function

import re
import subprocess

from statick_tool.issue import Issue
from statick_tool.tool_plugin import ToolPlugin


class FortifyToolPlugin(ToolPlugin):
    """Apply Fortify tool and gather results."""

    def get_name(self):
        """Get name of tool."""
        return "Fortify"

    def scan(self, package, level):
        """Run tool and gather output."""
        flags = []
        flags += self.get_user_flags(level)

        total_output = []

        with open(self.get_name() + ".log", "w") as f:
            for output in total_output:
                f.write(output)

        issues = self.parse_output(total_output)
        return issues

    def parse_output(self, total_output):
        """Parse tool output and report issues."""
        fortify_re = r"(.+):(\d+):\s(.+)\s:\s(.+)"
        parse = re.compile(fortify_re)
        issues = []

        for output in total_output:
            for line in output.split("\n"):
                match = parse.match(line)
                if match:
                    issues.append(Issue(match.group(1), match.group(2),
                                        self.get_name(), match.group(3), "5",
                                        match.group(4), None))

        return issues
