"""Unit tests for the fortify tool module."""
import argparse
import os
import subprocess
import tempfile
import xml.etree.ElementTree as etree

import mock
import statick_tool
from statick_tool.config import Config
from statick_tool.package import Package
from statick_tool.plugin_context import PluginContext
from statick_tool.plugins.tool.fortify_plugin.fortify_tool_plugin import \
    FortifyToolPlugin
from statick_tool.resources import Resources
from statick_tool.tool_plugin import ToolPlugin
from yapsy.PluginManager import PluginManager


def setup_fortify_tool_plugin():
    """Create an instance of the fortify plugin."""
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("--show-tool-output", dest="show_tool_output",
                            action="store_true", help="Show tool output")
    arg_parser.add_argument("--fortify-python", dest="fortify_python", type=int)

    resources = Resources([os.path.join(os.path.dirname(statick_tool.__file__),
                                        'plugins')])
    config = Config(resources.get_file("config.yaml"))
    plugin_context = PluginContext(arg_parser.parse_args([]), resources, config)
    ftp = FortifyToolPlugin()
    ftp.set_plugin_context(plugin_context)
    return ftp


def test_fortify_tool_plugin_found():
    """Test that the fortify tool plugin is detected by the plugin system."""
    manager = PluginManager()
    # Get the path to statick_tool/__init__.py, get the directory part, and
    # add 'plugins' to that to get the standard plugins dir
    manager.setPluginPlaces([os.path.join(os.path.dirname(statick_tool.__file__),
                                          'plugins')])
    manager.setCategoriesFilter({
        "Tool": ToolPlugin,
    })
    manager.collectPlugins()
    # Verify that a plugin's get_name() function returns "fortify"
    assert any(plugin_info.plugin_object.get_name() == 'fortify' for
               plugin_info in manager.getPluginsOfCategory("Tool"))
    # While we're at it, verify that a plugin is named Fortify Tool Plugin
    assert any(plugin_info.name == 'Fortify Tool Plugin' for
               plugin_info in manager.getPluginsOfCategory("Tool"))


def sideeffect_python_found(*args, **kwargs):
    """Custom side effect for patching subprocess.check_output."""
    if 'sourceanalyzer' in args[0]:
        # I don't actually have an example of what the output looks like
        return "Nothing to see here"
    else:
        return ""


def test_fortify_python_available_valid():
    # Set up
    ftp = setup_fortify_tool_plugin()
    tmp_file = tempfile.TemporaryFile()
    with mock.patch.object(subprocess, 'check_output', side_effect=sideeffect_python_found):
        assert ftp._fortify_python_available(tmp_file)


def sideeffect_python_not_found(*args, **kwargs):
    """Custom side effect for patching subprocess.check_output."""
    if 'sourceanalyzer' in args[0]:
        return "[error]: Your license does not allow access to Fortify SCA for Python\n\
com.fortify.licensing.UnlicensedCapabilityException: Your license does not allow access to Fortify SCA for Python\n\
at com.fortify.licensing.Licensing.getCapabilityConfig(Licensing.java:120) ~[fortify-common-18.20.0.1071.jar:?]\n\
at com.fortify.licensing.Licensing.requireCapability(Licensing.java:63) ~[fortify-common-18.20.0.1071.jar:?]\n\
at com.fortify.sca.frontend.Python3FrontEnd.runTranslator(Python3FrontEnd.java:158) [fortify-sca-18.20.1071.jar:?]\n\
at com.fortify.sca.frontend.FrontEndSession.runSingleFrontEnd(FrontEndSession.java:231) [fortify-sca-18.20.1071.jar:?]\n\
at com.fortify.sca.frontend.FrontEndSession.runFrontEnd(FrontEndSession.java:193) [fortify-sca-18.20.1071.jar:?]\n\
at com.fortify.sca.Main$Sourceanalyzer.run(Main.java:527) [fortify-sca-18.20.1071.jar:?]"
    else:
        return ""


def test_fortify_python_available_invalid():
    # Set up
    ftp = setup_fortify_tool_plugin()
    tmp_file = tempfile.TemporaryFile()
    with mock.patch.object(subprocess, 'check_output', side_effect=sideeffect_python_not_found):
        assert not ftp._fortify_python_available(tmp_file)


def test_fortify_parse_class_audit():
    """Test that we can parse a stripped-down sample fvdl file with a class vulnerability."""
    package = Package('test', os.path.dirname(__file__))
    ftp = setup_fortify_tool_plugin()
    tree = etree.parse(os.path.join(os.path.dirname(__file__),
                                    'class_audit.fvdl'))
    root = tree.getroot()
    issues = ftp.parse_output(root, package)
    assert len(issues) == 1
    assert issues[0].filename
    assert issues[0].line_number == '542'
    assert issues[0].tool == 'fortify'
    assert issues[0].issue_type == 'structural'
    assert issues[0].severity == '3'
    assert issues[0].message


def test_fortify_parse_function_audit():
    """Test that we can parse a stripped-down sample fvdl file with a function vulnerability."""
    package = Package('test', os.path.dirname(__file__))
    ftp = setup_fortify_tool_plugin()
    tree = etree.parse(os.path.join(os.path.dirname(__file__),
                                    'function_audit.fvdl'))
    root = tree.getroot()
    issues = ftp.parse_output(root, package)
    assert len(issues) == 1
    assert issues[0].filename
    assert issues[0].line_number == '279'
    assert issues[0].tool == 'fortify'
    assert issues[0].issue_type == 'dataflow'
    assert issues[0].severity == '3'
    assert issues[0].message


def test_fortify_parse_nocontext_audit():
    """Test that we can parse a stripped-down sample fvdl file with a vulnerability with empty context."""
    package = Package('test', os.path.dirname(__file__))
    ftp = setup_fortify_tool_plugin()
    tree = etree.parse(os.path.join(os.path.dirname(__file__),
                                    'nocontext_audit.fvdl'))
    root = tree.getroot()
    issues = ftp.parse_output(root, package)
    assert len(issues) == 1
    assert issues[0].filename
    assert issues[0].line_number == '1'
    assert issues[0].tool == 'fortify'
    assert issues[0].issue_type == 'configuration'
    assert issues[0].severity == '2'
    assert issues[0].message
