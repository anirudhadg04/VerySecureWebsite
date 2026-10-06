from pathlib import Path
p = Path('app/templates/terminal.html')
s = p.read_text(encoding='utf-8')
start = s.index('{% block extra_js %}')
end = s.rindex('{% endblock %}') + len('{% endblock %}')
replacement = '{% block extra_js %}\n<script>\n' + Path('.terminal-script.tmp').read_text(encoding='utf-8') + '\n</script>\n{% endblock %}'
p.write_text(s[:start] + replacement + s[end:], encoding='utf-8')
