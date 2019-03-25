"""Plugin to perform analysis using MicroFocus Fortify SCA."""

from __future__ import print_function

import os
import subprocess
import sys
import xml.etree.ElementTree as etree
import zipfile

from statick_tool.issue import Issue
from statick_tool.tool_plugin import ToolPlugin


class FortifyToolPlugin(ToolPlugin):
    """Apply Fortify tool and gather results."""

# pylint: disable=no-self-use
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
# pylint: enable=no-self-use

# pylint: disable=too-many-branches, too-many-return-statements
    def scan(self, package, _):
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
            return []

        if not self.command_exists('FPRUtility'):
            print("Couldn't find 'FPRUtility' command, can't run Fortify plugin")
            return []

        with open(self.get_name() + ".log", "wt") as outfile:
            if package['top_poms']:
                print("  Performing Maven scan")
                self._scan_maven(package, outfile)

            if package['python_src']:
                if self._fortify_python_available(outfile):
                    print("  Fortify Python license found")
                    self._scan_python(package, outfile)
                else:
                    print("  Fortify Python license not found, can't scan Python files")

            # Generate the combined .fpr
            print("  Generating .fpr file")
            try:
                output = subprocess.check_output(["sourceanalyzer", "-b",
                                                  _get_build_name(package), "-scan", "-f",
                                                  "{}.fpr".format(os.path.join(os.getcwd(),
                                                                               _get_build_name(package)))],  # pylint: disable=line-too-long
                                                 stderr=subprocess.STDOUT,
                                                 universal_newlines=True)
                if self.plugin_context.args.show_tool_output:
                    print(output)
                outfile.write(output.encode())
            except subprocess.CalledProcessError as ex:
                outfile.write(output.encode())
                print("sourceanalyzer scan failed! Returncode = {}".format(ex.returncode))
                print(output)
                return []
            except OSError as ex:
                print("Failed to run sourceanalyzer: {}".format(ex))
                return []

            print("  Extracting report from fpr file")

            # an fpr file is just a ZIP file with a non-standard extension
            try:
                with zipfile.ZipFile("{}.fpr".format(_get_build_name(package)), mode='r') \
                        as fpr_zip:
                    if 'audit.fvdl' not in fpr_zip.namelist():
                        print("  Couldn't find audit.fvdl in fpr!")
                        return []
                    # audi.fvdl is the file with the actual scan results
                    fpr_zip.extract('audit.fvdl')

            # Yes, the Zipfile spelling is deprecated, but we want it for py2.7 compatibility
            except zipfile.BadZipfile as ex:
                outfile.write(ex)
                print("  Error unzipping .fpr file: {}".format(ex))
                return []

            # And the .fvdl is just an XML file
            tree = etree.parse('audit.fvdl')
            root = tree.getroot()
            issues = self.parse_output(root, package)
            return issues
# pylint: enable=too-many-branches, too-many-return-statements

    def _scan_maven(self, package, outfile):
        """Run the Fortify Maven plugin."""
        # Sanity check - make sure mvn exists
        if not self.command_exists('mvn'):
            print("Couldn't find 'mvn' command, can't run Fortify Maven integration")
            return False

        # Sanity check - make sure that the user has the Fortify plugin available
        try:
            output = subprocess.check_output(["mvn", "dependency:get",
                                              "-DgroupId=com.fortify.sca.plugins.maven",
                                              "-DartifactId=sca-maven-plugin",
                                              "-Dversion={}".format(self.plugin_context.args.
                                                                    fortify_version)],
                                             universal_newlines=True)
            if self.plugin_context.args.show_tool_output:
                print(output)
            outfile.write(output.encode())
        except subprocess.CalledProcessError as ex:
            outfile.write(ex.output.encode())
            print("Couldn't find sca-maven-plugin! Make sure you have installed it. Error: {}".
                  format(ex))
            return False
        except OSError as ex:
            print("Error calling maven: {}".format(ex))
            return False

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
                    print(output)
                outfile.write(output.encode())
            except subprocess.CalledProcessError as ex:
                outfile.write(ex.output.encode())
                print("mvn clean install failed! Returncode = {}".format(ex.returncode))
                print(ex.output)
                # Don't fail the plugin just for one POM failing

            # Run the translate stage for this POM
            print("  Translating {}".format(pom))
            try:
                output = subprocess.check_output(["sourceanalyzer", "-b",
                                                  _get_build_name(package), "mvn",
                                                  "com.fortify.sca.plugins.maven:"
                                                  "sca-maven-plugin:translate"],
                                                 cwd=os.path.dirname(pom),
                                                 stderr=subprocess.STDOUT,
                                                 universal_newlines=True)
                if self.plugin_context.args.show_tool_output:
                    print(output)
                outfile.write(output.encode())
            except subprocess.CalledProcessError as ex:
                outfile.write(ex.output.encode())
                print("Fortify translate failed! Returncode = {}".format(ex.returncode))
                print(ex.output)
                # Don't fail the plugin just for one POM failing
        return True

    def _scan_python(self, package, outfile):
        """
        Scan Python files.

        Caveat: I don't actually have access to the Python plugin, so this might not be correct.
        """
        python_path_ext = []
        # pylint: disable=no-member
        if 'PYTHONPATH' in os.environ:
            python_path_ext = ["-python-path", os.envrion['PYTHONPATH']]
        # pylint: enable=no-member
        for filename in package['python_src']:
            try:
                output = subprocess.check_output(["sourceanalyzer", "-b",
                                                  _get_build_name(package), "-python-version",
                                                  "{}".format(self.plugin_context
                                                              .args.fortify_python),
                                                  filename] + python_path_ext,
                                                 stderr=subprocess.STDOUT,
                                                 universal_newlines=True)
                if self.plugin_context.args.show_tool_output:
                    print(output)
                outfile.write(output.encode())

            except subprocess.CalledProcessError as ex:
                outfile.write(ex.output.encode())
                print("Fortify python scan failed on file {}! Returncode = {}".
                      format(filename, ex.returncode))
                # Don't fail for one scan failure - Fortify particularly has issues with
                # python files that don't end in .py
            except OSError as ex:
                # This, on the other hand, is probably a fatal error, bail out.
                print("Failed to run sourceanalyzer: {}".format(ex))
                return

    def _fortify_python_available(self, outfile):
        """
        Check if Fortify is licensed to scan Python files.

        Python support in Fortify is sold as part of an add-on package. Check
        whether the user has the appropriate license or not.
        """
        print("  Checking if Fortify is licensed to scan Python...")
        # Create a test python file to scan
        try:
            output = subprocess.check_output(["touch", "statick-fortify-check.py"],
                                             universal_newlines=True)
            if self.plugin_context.args.show_tool_output:
                print(output)
            outfile.write(output.encode())

        except OSError as ex:
            print("Couldn't touch the python test file: {}".format(ex))
            return False

        except subprocess.CalledProcessError as ex:
            outfile.write(ex.output.encode())
            print("Couldn't create Python test file! Returncode = {}".format(ex.returncode))
            print(ex.output)
            return False

        # Check for the python-not-supported error
        try:
            output = subprocess.check_output(["sourceanalyzer", "-b",
                                              "statick-python-check", "-python-version",
                                              "{}".format(self.plugin_context.args.fortify_python),
                                              'statick-fortify-check.py'],
                                             stderr=subprocess.STDOUT,
                                             universal_newlines=True)
            if self.plugin_context.args.show_tool_output:
                print(output)
            outfile.write(output.encode())
            if "[error]: Your license does not allow access to Fortify SCA for Python" \
                    in output.splitlines():
                # Means exactly what it sounds like. Python not available.
                return False
            return True

        except subprocess.CalledProcessError as ex:
            outfile.write(ex.output)
            print("Python availability check failed! Returncode = {}".format(ex.returncode))
            print(ex.output)
            return False

        except OSError as ex:
            print("Failed to run sourceanalyzer: {}".format(ex))
            return False

# pylint: disable=too-many-locals
    def parse_output(self, xml_root, package):
        """Parse tool XML output and report issues."""
        namespace = {"default": "xmlns://www.fortifysoftware.com/schema/fvdl"}
        issues = []
        vulnerabilities = xml_root.find('default:Vulnerabilities', namespaces=namespace)
        # Load the plugin mapping if possible
        warnings_mapping = self.load_mapping()

        for vulnerability in list(vulnerabilities):
            type_ = vulnerability.find("default:ClassInfo/default:Type",
                                       namespaces=namespace).text
            description = "{}, {}".format(vulnerability.find("default:ClassInfo/default:Kingdom",
                                                             namespaces=namespace).text,
                                          type_)
            if vulnerability.find("default:ClassInfo/default:Subtype",
                                  namespaces=namespace) is not None:
                description += ", {}".format(vulnerability.find("default:ClassInfo/default:Subtype",
                                                                namespaces=namespace).text)
            analyzer_name = vulnerability.find("default:ClassInfo/default:AnalyzerName",
                                               namespaces=namespace).text
            description += ", {} ".format(analyzer_name)
            severity = vulnerability.find("default:InstanceInfo/default:InstanceSeverity",
                                          namespaces=namespace).text
            context = vulnerability.find("default:AnalysisInfo/default:Unified/default:Context",
                                         namespaces=namespace)
            default_node = vulnerability.find("default:AnalysisInfo/default:Unified/default:Trace/"
                                              "default:Primary/default:Entry/default:Node["
                                              "@isDefault='true']", namespaces=namespace)
            line = default_node.find('default:SourceLocation', namespaces=namespace).attrib['line']
            path = os.path.join(package.path, default_node.find('default:SourceLocation',
                                                                namespaces=namespace)
                                .attrib['path'])

            for action_node in default_node.findall('default:Action', namespaces=namespace):
                if 'type' in action_node.attrib:
                    description += "{}: {} ".format(action_node.attrib['type'], action_node.text)
                else:
                    description += "{} ".format(action_node.text)

            # Pull context where possible
            # pylint: disable=line-too-long
            if context is not None:
                if context.find("default:Function", namespaces=namespace) is not None:
                    function = context.find("default:Function", namespaces=namespace)
                    if 'namespace' in function.attrib:
                        description += "in function {}, class {}.{}".format(function.attrib['name'],
                                                                            function.attrib['namespace'],
                                                                            function.attrib['enclosingClass'])
                    else:
                        description += "in function {}, class {}".format(function.attrib['name'],
                                                                         function.attrib['enclosingClass'])

                elif context.find("default:ClassIdent", namespaces=namespace) is not None:
                    class_ident = context.find("default:ClassIdent", namespaces=namespace)
                    description += "in class {}.{}".format(class_ident.attrib['namespace'],
                                                           class_ident.attrib['name'])
            cert_reference = warnings_mapping.get(type_, None)
            issues.append(Issue(path, line, self.get_name(), analyzer_name,
                                "{:.0f}".format(float(severity)), description,
                                cert_reference))
        # pylint: enable=line-too-long
        return issues
# pylint: enable=too-many-locals


def _get_build_name(package):
    """Generate the name passed to Fortify."""
    return "statick-fortify-{}".format(package.name)
