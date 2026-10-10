from cvss import base_score

threats = {
    "T-01": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "T-02": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "T-03": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N",
    "T-04": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
    "T-05": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "T-06": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "T-07": "CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "T-08": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "T-09": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "T-10": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",
    "T-11": "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "T-12": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N",
    "T-13": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "T-14": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "T-15": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
    "T-16": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
}


def level(score):
    if score == 0:
        return "немає"
    if score < 4.0:
        return "низький"
    if score < 7.0:
        return "середній"
    if score < 9.0:
        return "високий"
    return "критичний"


high = 0
top = "T-01"
for tid, vector in threats.items():
    score = base_score(vector)
    print(tid, vector, score, level(score))
    if score >= 7.0:
        high += 1
    if score > base_score(threats[top]):
        top = tid

print()
print("усього загроз:", len(threats))
print("високого ризику:", high)
print("найкритичніша:", top, base_score(threats[top]))
