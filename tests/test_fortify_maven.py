"""Unit tests for the fortify tool module's maven methods."""
import os
import subprocess
import tempfile

import mock

from statick_tool.package import Package


@mock.patch('statick_tool.plugins.tool.fortify_plugin.fortify_tool_plugin.ToolPlugin.command_exists')
@mock.patch('statick_tool.plugins.tool.fortify_plugin.fortify_tool_plugin.subprocess.check_output')
def test_fortify_maven_not_available(check_output_mock, command_exists_mock, fortify_tool_plugin):
    """Test behavior when command_exists says maven is unavailable."""
    command_exists_mock.return_value = False
    package = Package('test', os.path.dirname(__file__))
    with tempfile.NamedTemporaryFile() as tmp_file:
        retval = fortify_tool_plugin._scan_maven(package, tmp_file)  # pylint: disable=protected-access
    # We should have returned before check_output gets called
    check_output_mock.assert_not_called()
    assert not retval


@mock.patch('statick_tool.plugins.tool.fortify_plugin.fortify_tool_plugin.subprocess.check_output')
def test_fortify_plugin_check_oserror(check_output_mock, fortify_tool_plugin):
    """Test behavior when command_exists says maven is unavailable."""
    check_output_mock.side_effect = OSError("error")
    package = Package('test', os.path.dirname(__file__))
    with tempfile.NamedTemporaryFile() as tmp_file:
        retval = fortify_tool_plugin._scan_maven(package, tmp_file)  # pylint: disable=protected-access
    assert not retval


@mock.patch('statick_tool.plugins.tool.fortify_plugin.fortify_tool_plugin.subprocess.check_output')
def test_fortify_plugin_check_calledprocesserror(check_output_mock, fortify_tool_plugin):
    """Test behavior when command_exists says maven is unavailable."""
    check_output_mock.side_effect = subprocess.CalledProcessError(1, "error", output="error")
    package = Package('test', os.path.dirname(__file__))
    with tempfile.NamedTemporaryFile() as tmp_file:
        retval = fortify_tool_plugin._scan_maven(package, tmp_file)  # pylint: disable=protected-access
    assert not retval
