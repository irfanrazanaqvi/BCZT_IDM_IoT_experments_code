"""Reorder \bibitem entries so reference numbers follow order of first citation in the text."""
import re
files = ["sec_intro", "sec_related", "sec_model", "sec_architecture", "sec_security",
         "sec_implementation", "sec_evaluation", "sec_discussion", "sec_conclusion"]
order = []
for f in files:
    t = open(f + ".tex").read()
    t = t.split("\\begin{thebibliography}")[0]
    for m in re.finditer(r"\\cite\{([^}]*)\}", t):
        for k in m.group(1).split(","):
            k = k.strip()
            if k not in order: order.append(k)
t = open("sec_conclusion.tex").read()
head, rest = t.split("\\begin{thebibliography}{99}")
pre, body = rest.split("\\bibitem", 1)
body, tail = ("\\bibitem" + body).split("\\end{thebibliography}")
items = {re.match(r"\\bibitem\{([^}]*)\}", b).group(1): b.strip() for b in re.split(r"(?=\\bibitem\{)", body) if b.strip()}
missing = [k for k in order if k not in items]; unused = [k for k in items if k not in order]
print("cited:", len(order), "items:", len(items), "missing:", missing, "unused:", unused)
new = "\n\n".join(items[k] for k in order if k in items)
open("sec_conclusion.tex", "w").write(head + "\\begin{thebibliography}{99}" + pre + new.strip() + "\n\n\\end{thebibliography}" + tail)
