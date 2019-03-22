"""Unit tests for the fortify tool module."""
import argparse
import os

import pytest

import statick_tool
from statick_tool.config import Config
from statick_tool.plugin_context import PluginContext
from statick_tool.plugins.tool.fortify_plugin.fortify_tool_plugin import \
    FortifyToolPlugin
from statick_tool.resources import Resources


@pytest.fixture(scope="package")
def fortify_tool_plugin():
    """Create an instance of the fortify plugin."""
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("--show-tool-output", dest="show_tool_output",
                            action="store_true", help="Show tool output")
    arg_parser.add_argument("--fortify-python", dest="fortify_python", type=int)
    arg_parser.add_argument("--mapping-file-suffix", dest="mapping_file_suffix",
                            default=None)

    resources = Resources([os.path.join(os.path.dirname(statick_tool.__file__),
                                        'plugins')])
    config = Config(resources.get_file("config.yaml"))
    plugin_context = PluginContext(arg_parser.parse_args([]), resources, config)
    ftp = FortifyToolPlugin()
    ftp.set_plugin_context(plugin_context)
    return ftp
