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
                          choices={2, 3}, default=2)
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

        with open(self.get_name() + ".log", "w") as outfile:
            if package['top_poms']:
                print("  Performing Maven scan")
                self._scan_maven(package, outfile)

            if self._fortify_python_available(outfile):
                pass

            # Generate the combined .fpr
            print("  Generating .fpr report")
            try:
                output = subprocess.check_output(["sourceanalyzer", "-b",
                                                  self._get_build_name(package), "-scan", "-f",
                                                  "{}.fpr".format(os.path.join(os.getcwd(),
                                                                               self._get_build_name(package)))],
                                                 stderr=subprocess.STDOUT,
                                                 universal_newlines=True)
                if self.plugin_context.args.show_tool_output:
                    print("{}".format(output))
                outfile.write(output)
            except subprocess.CalledProcessError as ex:
                outfile.write(ex.output)
                print("sourceanalyzer scan failed! Returncode = {}".format(ex.returncode))
                print("{}".format(ex.output))

    def _get_build_name(self, package):
        return "statick-fortify-{}".format(package.name)

    def _scan_maven(self, package, outfile):
        """Run the Fortify Maven plugin."""

        # Sanity check - make sure mvn exists
        if not self.command_exists('mvn'):
            print("Couldn't find 'mvn' command, can't run Fortify Maven integration")
            return

        # Sanity check - make sure that the user has the Fortify plugin available
        try:
            output = subprocess.check_output(["mvn", "dependency:get",
                                              "-DgroupId=com.fortify.sca.plugins.maven",
                                              "-DartifactId=sca-maven-plugin",
                                              "-Dversion={}".format(self.plugin_context.args.fortify_version)],
                                             universal_newlines=True)
            if self.plugin_context.args.show_tool_output:
                print("{}".format(output))
            outfile.write(output)
        except subprocess.CalledProcessError as ex:
            outfile.write(ex.output)
            print("Couldn't find sca-maven-plugin! Make sure you have installed it.")
            return

        # Rebuild and translate each of the top poms
        for pom in package['top_poms']:
            # Prep for the analyzer run with a mvn clean install (recommended in the docs)
            print("  Building {}".format(pom))
            try:
                output = subprocess.check_output(["mvn", "clean", "install"],
                                                 cwd=os.path.dirname(pom),
                                                 stderr=subprocess.STDOUT,
                                                 universal_newlines=True)
                if self.plugin_context.args.show_tool_output:
                    print("{}".format(output))
                outfile.write(output)
            except subprocess.CalledProcessError as ex:
                outfile.write(ex.output)
                print("mvn clean install failed! Returncode = {}".format(ex.returncode))
                print("{}".format(ex.output))
                # Don't fail the plugin just for one POM failing

            # Run the translate stage for this POM
            print("  Translating {}".format(pom))
            try:
                output = subprocess.check_output(["sourceanalyzer", "-b",
                                                  self._get_build_name(package), "mvn",
                                                  "com.fortify.sca.plugins.maven:sca-maven-plugin:translate"],
                                                 cwd=os.path.dirname(pom),
                                                 stderr=subprocess.STDOUT,
                                                 universal_newlines=True)
                if self.plugin_context.args.show_tool_output:
                    print("{}".format(output))
                outfile.write(output)
            except subprocess.CalledProcessError as ex:
                outfile.write(ex.output)
                print("Fortify translate failed! Returncode = {}".format(ex.returncode))
                print("{}".format(ex.output))
                # Don't fail the plugin just for one POM failing

    def _fortify_python_available(self, outfile):
        """
        Check if Fortify is licensed to scan Python files.

        Python support in Fortify is sold as part of an add-on package. Check
        whether the user has the appropriate license or not.
        """
        print("Checking if Fortify is licensed to scan Python...")
        # Create a test python file to scan
        try:
            output = subprocess.check_output(["touch", "statick-fortify-check.py"],
                                             universal_newlines=True)
            if self.plugin_context.args.show_tool_output:
                print("{}".format(output))
            outfile.write(output)

        except subprocess.CalledProcessError as ex:
            outfile.write(ex.output)
            print("Couldn't create Python test file! Returncode = {}".format(ex.returncode))
            print("{}".format(ex.output))
            return False

        # Check for the python-not-supported error
        try:
            output = subprocess.check_output(["sourceanalyzer", "-b",
                                              "statick-python-check", "-python-version",
                                              "{}".format(self.plugin_context.args.fortify_python),
                                              'statick-fortify-check.py'],
                                             universal_newlines=True)
            if self.plugin_context.args.show_tool_output:
                print("{}".format(output))
            outfile.write(output)
            if "[error]: Your license does not allow access to Fortify SCA for Python" in output:
                # Means exactly what it sounds like. Python not available.
                return False
            return True

        except subprocess.CalledProcessError as ex:
            outfile.write(ex.output)
            print("Python availability check failed! Returncode = {}".format(ex.returncode))
            print("{}".format(ex.output))
            return False

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
