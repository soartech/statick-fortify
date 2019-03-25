"""Unit tests for the fortify tool module."""
import subprocess
import tempfile

import mock


def sideeffect_python_found(*args, **kwargs):  # pylint: disable=unused-argument
    """Custom side effect for patching subprocess.check_output."""
    if 'sourceanalyzer' in args[0]:
        return "Nothing to see here"
    return ""


def test_fortify_python_available_valid(fortify_tool_plugin):
    """Test that python_available is True if the relevant line is found."""
    tmp_file = tempfile.TemporaryFile()
    with mock.patch.object(subprocess, 'check_output', side_effect=sideeffect_python_found):
        assert fortify_tool_plugin._fortify_python_available(tmp_file)  # pylint: disable=protected-access


def sideeffect_python_not_found(*args, **kwargs):  # pylint: disable=unused-argument
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
    return ""


def test_fortify_python_available_invalid(fortify_tool_plugin):
    """Test that python_available is False if the output doesn't include the relevant line."""
    tmp_file = tempfile.TemporaryFile()
    with mock.patch.object(subprocess, 'check_output', side_effect=sideeffect_python_not_found):
        assert not fortify_tool_plugin._fortify_python_available(tmp_file)  # pylint: disable=protected-access


@mock.patch('statick_tool.plugins.tool.fortify_plugin.fortify_tool_plugin.subprocess.check_output')
def test_fortify_python_available_touch_oserror(check_output_mock, fortify_tool_plugin):
    """Test that python_available is False if the output triggers an oserror."""
    check_output_mock.side_effect = OSError("error")
    with tempfile.NamedTemporaryFile() as tmp_file:
        assert not fortify_tool_plugin._fortify_python_available(tmp_file)  # pylint: disable=protected-access


@mock.patch('statick_tool.plugins.tool.fortify_plugin.fortify_tool_plugin.subprocess.check_output')
def test_fortify_python_available_touch_calledprocesserror(check_output_mock, fortify_tool_plugin):
    """Test that python_available is False if touch (test file) triggers a calledprocesserror."""
    check_output_mock.side_effect = subprocess.CalledProcessError(1, "error", output="Error")
    with tempfile.NamedTemporaryFile() as tmp_file:
        assert not fortify_tool_plugin._fortify_python_available(tmp_file)  # pylint: disable=protected-access
