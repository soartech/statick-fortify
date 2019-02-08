"""Plugin to perform analysis using MicroFocus Fortify SCA."""

from __future__ import print_function

import os
import re
import subprocess
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
                          help="version of Python to use for Fortify Python analysis",
                          choices={2, 3})
        args.add_argument("--fortify-version", dest="fortify_version", type=str,
                          help="version of Fortify to use", default="18.20")

    def scan(self, package, level):
        """Run tool and gather output."""

        if self.plugin_context.args.fortify_dir is not None:
            if os.path.isdir(self.plugin_context.args.fortify_dir):
                sys.path.insert(0, self.plugin_context.args.fortify_dir)
            else:
                print("Provided Fortify directory {} is not a directory!",
                      self.plugin_context.args.fortify_dir)

        # Sanity check - this plugin won't work without or FPRUtility
        if not self.command_exists('sourceanalyzer'):
            print("Couldn't find 'sourceanalyzer' command, can't run Fortify plugin")
            return None

        if not self.command_exists('FPRUtility'):
            print("Couldn't find 'FPRUtility' command, can't run Fortify plugin")
            return None

        issues = []
        total_output = []

        if package['top_poms']:
            maven_issues, maven_output = self.scan_maven(package)
            issues += maven_issues
            total_output += maven_output

        # Merge all FPR files together
        fpr_files = []
        for filename in os.listdir(os.getcwd()):
            if filename.endswith('.fpr'):
                fpr_files.append(filename)

        with open(self.get_name() + ".log", "w") as f:
            for output in total_output:
                f.write(output)


    def scan_maven(self, package):
        """Run the Fortify Maven plugin."""

        if not self.command_exists('mvn'):
            print("Couldn't find 'mvn' command, can't run Fortify Maven integration")
            return [], ''

        maven_output = []

        # Sanity check - make sure that the user has the Fortify plugin available
        try:
            output = subprocess.check_output(["mvn", "dependency:get", 
                                              "-DgroupId=com.fortify.sca.plugins.maven",
                                              "-DartifactId=sca-maven-plugin",
                                              "-Dversion={}".format(self.plugin_context.args.fortify_version)],
                                             universal_newlines=True)
            if self.plugin_context.args.show_tool_output:
                print("{}".format(output))
        except subprocess.CalledProcessError as ex:
            maven_output += ex.output
            print("Couldn't find sca-maven-plugin! Make sure you have installed it.")
            return [], maven_output

        maven_output += output

        build_name = "statick-fortify-{}".format(package.name)

        # Rebuild and translate each of the top poms
        for pom in package['top_poms']:
            # Prep for the analyzer run
            try:
                output = subprocess.check_output(["mvn", "clean", "install"],
                                                 cwd=os.path.dirname(pom),
                                                 stderr=subprocess.STDOUT,
                                                 universal_newlines=True)
                if self.plugin_context.args.show_tool_output:
                    print("{}".format(output))
            except subprocess.CalledProcessError as ex:
                maven_output += ex.output
                print("mvn clean install failed! Returncode = {}".format(ex.returncode))
                print("{}".format(ex.output))
                return [], maven_output

            try:
                output = subprocess.check_output(["sourceanalyzer", "-b",
                                                  build_name, "mvn",
                                                  "com.fortify.sca.plugins.maven:sca-maven-plugin:translate"],
                                                 cwd=os.path.dirname(pom),
                                                 stderr=subprocess.STDOUT,
                                                 universal_newlines=True)
                if self.plugin_context.args.show_tool_output:
                    print("{}".format(output))
            except subprocess.CalledProcessError as ex:
                maven_output += ex.output
                print("Fortify translate failed! Returncode = {}".format(ex.returncode))
                print("{}".format(ex.output))

        try:
            output = subprocess.check_output(["sourceanalyzer", "-b",
                                              build_name, "-scan", "-f",
                                              "{}.fpr".format(os.path.join(os.getcwd(),
                                                                           build_name))],
                                             cwd=os.path.dirname(pom),
                                             stderr=subprocess.STDOUT,
                                             universal_newlines=True)
            if self.plugin_context.args.show_tool_output:
                print("{}".format(output))
        except subprocess.CalledProcessError as ex:
            maven_output += ex.output
            print("mvn clean install failed! Returncode = {}".format(ex.returncode))
            print("{}".format(ex.output))
            return [], maven_output

        maven_output += output

        #issues = self.parse_output(total_output)
        return [], maven_output


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
