
import re

with open(r'c:\MoodWave\dashboard.html', 'r', encoding='utf-8') as f:
    content = f.read()

tags = re.findall(r'<(/?[a-zA-Z0-9]+)', content)
stack = []
for tag in tags:
    if tag.startswith('/'):
        tag_name = tag[1:]
        if not stack:
            print(f"Unexpected closing tag: </{tag_name}>")
        else:
            top = stack.pop()
            if top != tag_name:
                print(f"Mismatched tags: <{top}> closed by </{tag_name}>")
                while stack and stack[-1] != tag_name:
                    stack.pop()
                if stack:
                    stack.pop()
    else:
        if tag.lower() not in ['img', 'br', 'hr', 'input', 'link', 'meta', 'source']:
            stack.append(tag)

if stack:
    print(f"Unclosed tags: {stack}")
else:
    print("Tags appear balanced")
