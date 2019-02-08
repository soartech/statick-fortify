"""Plugin to perform analysis using MicroFocus Fortify SCA."""

from __future__ import print_function

import os
import re
import sys

from statick_tool.issue import Issue
from statick_tool.tool_plugin import ToolPlugin


class FortifyToolPlugin(ToolPlugin):
    """Apply Fortify tool and gather results."""

    def get_name(self):
        """Get name of tool."""
        return "fortify"

    def gather_args(self, args):
        """Gather arguments."""
        args.add_argument("--fortify-dir", dest="fortify_dir", type=str,
                          help="path to Fortify directory")
        args.add_argument("--fortify-python", dest="fortify_python", type=int,
                          help="version of Python to use for Fortify Python analysis"
                          choices={2, 3})


    def scan(self, package, level):
        """Run tool and gather output."""

        if self.plugin_context.args.fortify_dir is not None:
            if os.path.isdir(self.plugin_context.args.fortify_dir):
                sys.path.insert(0, self.plugin_context.args.fortify_dir)
            else:
                print("Provided Fortify directory {} is not a directory!",
                      self.plugin_context.args.fortify_dir)

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
