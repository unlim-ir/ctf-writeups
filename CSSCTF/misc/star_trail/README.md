# Writeup: A Star Trail 

> **دسته‌بندی:** Misc

> **فایل چالش:** `A_Star_Trail.png`

> **فرمت فلگ:** `CSSCTF{}`

---

## 1. صورت چالش

یک نقشه‌ی ستاره‌ای (Polaris Logistics Star Map) داده شده. باید یک بسته‌ی VIP را از **Earth** به **Lancer-RXKRD** برسانیم، با این شرایط:

- فقط از **مسیرهای مشخص‌شده** بین سیاره‌ها/سیارک‌ها می‌شود رفت.
- کل سفر باید **کمتر از ۲۵ روز** طول بکشد.
- فلگ = **حرف اول هر سیاره‌ی مسیر** + `-` + **مجموع روزها** (مثلاً `CSSCTF{POST2-5.0}`).
- مسیر باید **کوتاه‌ترین** مسیر ممکن باشد.

---

## 2. تبدیل تصویر به گراف

هر سیاره یک **گره** و هر خط‌چین یک **یال** است. عدد کنار هر خط‌چین **وزن یال** (تعداد روز) است.

| از | به | روز |
|---|---|---|
| Earth | Baconite | 5.0 |
| Earth | Pallus-XA | 10.7 |
| Baconite | C3810-Asquax-8 | 2.1 |
| Baconite | Barat-Barat | 9.8 |
| C3810-Asquax-8 | Barat-Barat | 6.3 |
| Barat-Barat | Jip-Reia | 1.4 |
| Barat-Barat | Pallus-XA | 1.4 |
| Jip-Reia | 12-Puck-8 | 0.4 |
| Jip-Reia | Taylor-3489 | 5.5 |
| 12-Puck-8 | Pallus-XA | 1.8 |
| 12-Puck-8 | Hemens-Raja-2 | 3.6 |
| Pallus-XA | Hemens-Raja-2 | 2.5 |
| Hemens-Raja-2 | Tammy Asteroid | 3.7 |
| Hemens-Raja-2 | 10-49-Slater-4090 | 6.0 |
| Taylor-3489 | Tammy Asteroid | 3.2 |
| Taylor-3489 | Lancer-RXKRD | 2.6 |
| Tammy Asteroid | Verginon | 2.8 |
| Tammy Asteroid | Lancer-RXKRD | 10.1 |
| Verginon | Lancer-RXKRD | 8.5 |
| Verginon | 10-49-Slater-4090 | 7.5 |


---

## 3. حل: الگوریتم 


### مقایسه‌ی مسیرهای اصلی

| مسیر | مجموع روز |
|---|---|
| Earth → Pallus → **12-Puck-8** → Jip-Reia → Taylor → Lancer | **21.0** ✅ |
| Earth → Pallus → Barat-Barat → Jip-Reia → Taylor → Lancer | 21.6 |
| Earth → Pallus → Hemens → Tammy → Taylor → Lancer | 22.7 |
| Earth → Baconite → C3810 → Barat-Barat → Jip-Reia → Taylor → Lancer | 22.9 |
| Earth → Pallus → Hemens → Tammy → Lancer | 27.0 ❌ (بیشتر از ۲۵) |

### مسیر بهینه

```text
Earth → Pallus-XA → 12-Puck-8 → Jip-Reia → Taylor-3489 → Lancer-RXKRD
 10.7      1.8         0.4          5.5          2.6      = 21.0 روز
```

---

## 4. ساخت فلگ

حرف اول هر گره:

| گره | حرف اول |
|---|---|
| **E**arth | E |
| **P**allus-XA | P |
| **1**2-Puck-8 | 1 |
| **J**ip-Reia | J |
| **T**aylor-3489 | T |
| **L**ancer-RXKRD | L |



```text
CSSCTF{EP1JTL-21.0}
```

---

## 5. اسکریپت راستی‌آزمایی (Python)

```python
import heapq

edges = [
    ("Earth", "Baconite", 5.0), ("Earth", "Pallus-XA", 10.7),
    ("Baconite", "C3810-Asquax-8", 2.1), ("Baconite", "Barat-Barat", 9.8),
    ("C3810-Asquax-8", "Barat-Barat", 6.3),
    ("Barat-Barat", "Jip-Reia", 1.4), ("Barat-Barat", "Pallus-XA", 1.4),
    ("Jip-Reia", "12-Puck-8", 0.4), ("Jip-Reia", "Taylor-3489", 5.5),
    ("12-Puck-8", "Pallus-XA", 1.8), ("12-Puck-8", "Hemens-Raja-2", 3.6),
    ("Pallus-XA", "Hemens-Raja-2", 2.5),
    ("Hemens-Raja-2", "Tammy Asteroid", 3.7),
    ("Hemens-Raja-2", "10-49-Slater-4090", 6.0),
    ("Taylor-3489", "Tammy Asteroid", 3.2), ("Taylor-3489", "Lancer-RXKRD", 2.6),
    ("Tammy Asteroid", "Verginon", 2.8), ("Tammy Asteroid", "Lancer-RXKRD", 10.1),
    ("Verginon", "Lancer-RXKRD", 8.5), ("Verginon", "10-49-Slater-4090", 7.5),
]

graph = {}
for a, b, w in edges:
    graph.setdefault(a, []).append((b, w))
    graph.setdefault(b, []).append((a, w))

def dijkstra(src, dst):
    pq = [(0.0, src, [src])]
    seen = set()
    while pq:
        d, node, path = heapq.heappop(pq)
        if node == dst:
            return d, path
        if node in seen:
            continue
        seen.add(node)
        for nxt, w in graph[node]:
            if nxt not in seen:
                heapq.heappush(pq, (d + w, nxt, path + [nxt]))

dist, path = dijkstra("Earth", "Lancer-RXKRD")
letters = "".join(p[0] for p in path)
print(path)
print(f"CSSCTF{{{letters}-{dist:.1f}}}")   # CSSCTF{EP1JTL-21.0}
```

---

## 6. فلگ

```text
CSSCTF{EP1JTL-21.0}
```

---
