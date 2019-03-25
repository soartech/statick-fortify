"""Unit tests for the fortify tool module."""
import os

from yapsy.PluginManager import PluginManager

import statick_tool
import statick_tool.plugins.tool.fortify_plugin.fortify_tool_plugin as ftp_module
from statick_tool.package import Package
from statick_tool.tool_plugin import ToolPlugin


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


def test_fortify_get_build_name():
    """Test the get_build_name function."""
    package = Package('unusual-name', os.path.dirname(__file__))
    assert ftp_module._get_build_name(package) == \
        'statick-fortify-unusual-name'
