"""Unit tests for the fortify tool module."""
import subprocess
import tempfile

import mock


def sideeffect_python_found(*args, **kwargs):
    """Custom side effect for patching subprocess.check_output."""
    if 'sourceanalyzer' in args[0]:
        # I don't actually have an example of what the output looks like
        return "Nothing to see here"
    else:
        return ""


def test_fortify_python_available_valid(fortify_tool_plugin):
    # Set up
    tmp_file = tempfile.TemporaryFile()
    with mock.patch.object(subprocess, 'check_output', side_effect=sideeffect_python_found):
        assert fortify_tool_plugin._fortify_python_available(tmp_file)


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


def test_fortify_python_available_invalid(fortify_tool_plugin):
    # Set up
    tmp_file = tempfile.TemporaryFile()
    with mock.patch.object(subprocess, 'check_output', side_effect=sideeffect_python_not_found):
        assert not fortify_tool_plugin._fortify_python_available(tmp_file)