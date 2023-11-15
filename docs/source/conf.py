import os
import sys
import sphinx_rtd_theme
import yaml
from sphinx.highlighting import lexers
from pygments_lexer_solidity import SolidityLexer
lexers['solidity'] = SolidityLexer()
from pathlib import Path
# import subprocess

root_dir = Path(__file__).resolve().parents[2]
# subprocess.run('doxygen', shell=True, cwd=root_dir)

sys.path.insert(0, os.path.abspath('.'))

# -- General configuration ------------------------------------------------

# If your documentation needs a minimal Sphinx version, state it here.
#
# needs_sphinx = '1.0'

# Add any Sphinx extension module names here, as strm2rngs. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.


extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.doctest',
    'sphinx.ext.intersphinx',
    'sphinx.ext.todo',
    'sphinx.ext.ifconfig',
    'sphinx.ext.viewcode',
    'm2r2',
    'sphinx_extensions.iroha_permissions',
    "sphinxext.remoteliteralinclude"
]

html_static_path = ['_static']

html_context = {
    'css_files': [
        '_static/theme_overrides.css',  # override wide tables in RTD theme
        ],
     }
# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# The suffix(es) of source filenames.
# You can specify multiple suffix as a list of string:
source_suffix = ['.rst', '.md']

# The master toctree document.
master_doc = 'index'

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This patterns also effect to html_static_path and html_extra_path
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'sphinx'

# If true, `todo` and `todoList` produce output, else they produce nothing.
todo_include_todos = True

gettext_compact = False


# -- Options for HTML output ----------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "sphinx_rtd_theme"
html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]

# Custom sidebar templates, must be a dictionary that maps document names
# to template names.
#
# This is required for the alabaster theme
# refs: http://alabaster.readthedocs.io/en/latest/installation.html#sidebars
html_sidebars = {
    '**': [
        'relations.html',  # needs 'show_related': True theme option to display
        'searchbox.html',
    ]
}
html_theme_options = {
    'navigation_depth': 3, #default is 4 - changed for better looks
}

# Additional files
html_extra_path = ['_extra']

# -- Options for HTMLHelp output ------------------------------------------

# Output file base name for HTML help builder.
htmlhelp_basename = 'Irohadoc'


# -- Options for LaTeX output ---------------------------------------------

latex_elements = {
    # The paper size ('letterpaper' or 'a4paper').
    #
    # 'papersize': 'letterpaper',

    # The font size ('10pt', '11pt' or '12pt').
    #
    # 'pointsize': '10pt',

    # Additional stuff for the LaTeX preamble.
    #
    # 'preamble': '',

    # Latex figure (float) alignment
    #
    # 'figure_align': 'htbp',
}

# Read variables for
# common settings and locale:
with open('common.yaml', 'r') as stream:
    common = yaml.safe_load(stream)
    project = common.get('project')
    documentation = common.get('documentation')
    description = common.get('description')
    copyright = common.get('copyright')
    author = common.get('author')
with open('locale.yaml', 'r') as stream:
    locale = yaml.safe_load(stream)
    language = locale.get('language')
    if locale.get('locale_dirs'):
        print("Setting locale dir to " + locale.get('locale_dirs'))
        locale_dirs = [(locale.get('locale_dirs'))]


# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title,
#  author, documentclass [howto, manual, or own class]).
latex_documents = [
    (master_doc, 'Iroha.tex', documentation,
     author, 'manual'),
]


# -- Options for manual page output ---------------------------------------

# One entry per manual page. List of tuples
# (source start file, name, description, authors, manual section).
man_pages = [
    (master_doc, 'iroha', documentation,
     [author], 1)
]


# -- Options for Texinfo output -------------------------------------------

# Grouping the document tree into Texinfo files. List of tuples
# (source start file, target name, title, author,
#  dir menu entry, description, category)
texinfo_documents = [
    (master_doc, project, documentation,
     author, project, description,
     'C++'),
]


# -- Options for iroha_permissions extension ------------------------------
iroha_permissions_glossary_path = 'concepts_architecture/glossary.rst'
