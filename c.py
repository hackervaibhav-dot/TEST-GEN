import json
from datetime import datetime

input_file = "accounts.txt"     # isme tumhara uid:pass hoga
output_file = "output.json"     # ye json ban jayega

result = []
thread_id = 1

with open(input_file, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line or ":" not in line:
            continue

        uid, password = line.split(":", 1)

        data = {
            "uid": int(uid),
            "password": password,
            "account_id": str(int(uid) + 10000000000),  # fake account id generate
            "name": f"kamod{uid[-5:]}",                  # auto name
            "region": "IND",
            "date_created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "thread_id": thread_id
        }

        thread_id += 1
        result.append(data)

with open(output_file, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2, ensure_ascii=False)

print("✅ Done! output.json file ban gayi")