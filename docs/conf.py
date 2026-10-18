# Configuration file for the Sphinx documentation builder.
# crystal-pqc-constant: Post-Quantum Cryptography (ML-KEM & ML-DSA) for Crystal

project = 'crystal-pqc-constant'
copyright = '2026, Rénich Bon Ćirić (Copyleft)'
author = 'Rénich Bon Ćirić'
release = '0.1.1'

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.viewcode',
    'sphinx.ext.todo',
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'build', 'technical/api', 'Thumbs.db', '.DS_Store']

html_theme = 'sphinx_rtd_theme'
html_static_path = []
html_title = 'crystal-pqc-constant Documentation'
html_show_sourcelink = False
