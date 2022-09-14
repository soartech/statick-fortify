"""Unit tests for the fortify tool module."""
import os
import xml.etree.ElementTree as etree

from statick_tool.package import Package


def test_fortify_parse_class_audit(fortify_tool_plugin):
    """Test that we can parse a stripped-down sample fvdl file with a class vulnerability."""
    package = Package('test', os.path.dirname(__file__))
    tree = etree.parse(os.path.join(os.path.dirname(__file__),
                                    'class_audit.fvdl'))
    root = tree.getroot()
    issues = fortify_tool_plugin.parse_tool_output(root, package)
    assert len(issues) == 1
    assert issues[0].filename
    assert issues[0].line_number == '542'
    assert issues[0].tool == 'fortify'
    assert issues[0].issue_type == 'structural'
    assert issues[0].severity == '3'
    assert issues[0].message


def test_fortify_parse_function_audit(fortify_tool_plugin):
    """Test that we can parse a stripped-down sample fvdl file with a function vulnerability."""
    package = Package('test', os.path.dirname(__file__))
    tree = etree.parse(os.path.join(os.path.dirname(__file__),
                                    'function_audit.fvdl'))
    root = tree.getroot()
    issues = fortify_tool_plugin.parse_tool_output(root, package)
    assert len(issues) == 1
    assert issues[0].filename
    assert issues[0].line_number == '279'
    assert issues[0].tool == 'fortify'
    assert issues[0].issue_type == 'dataflow'
    assert issues[0].severity == '3'
    assert issues[0].message


def test_fortify_parse_nocontext_audit(fortify_tool_plugin):
    """Test that we can parse an fvdl file with a vulnerability with empty context."""
    package = Package('test', os.path.dirname(__file__))
    tree = etree.parse(os.path.join(os.path.dirname(__file__),
                                    'nocontext_audit.fvdl'))
    root = tree.getroot()
    issues = fortify_tool_plugin.parse_tool_output(root, package)
    assert len(issues) == 1
    assert issues[0].filename
    assert issues[0].line_number == '1'
    assert issues[0].tool == 'fortify'
    assert issues[0].issue_type == 'configuration'
    assert issues[0].severity == '2'
    assert issues[0].message
