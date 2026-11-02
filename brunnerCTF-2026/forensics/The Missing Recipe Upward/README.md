***The Missing Recipe***


**مسابقه:** Brunner 2026
 **دسته‌بندی :**  Forensics/
**سختی:** متوسط

**نویسنده:** N1ghtL0rd

---

## مقدمه



چند نفر از شرکت‌کنندگان [بوت‌کمپ هک آنلیم (تابستان ۱۴۰۵)](https://unlim.ir/bootcamps/ctf) تصمیم گرفتیم این بار چیزهایی را که در طول بوت‌کمپ یاد گرفته بودیم، در یک مسابقه‌ی واقعی محک بزنیم.

برای همین یک تیم تشکیل دادیم و در **Brunner 2026**،
یک CTF بین‌المللی، شرکت کردیم. در طول مسابقه، هرکدام از اعضای تیم سراغ
چالش‌های مختلفی رفتیم و در نهایت توانستیم مجموعه‌ای از آن‌ها را حل کنیم.

این Writeup حاصل تلاش تیم برای حل چالش **The Missing Recipe** است و در ادامه، مسیر تحلیل و راه‌حلی که به Flag منتهی شد را قدم‌به‌قدم بررسی می‌کنیم.

---

## صورت مسئله

در توضیح چالش گفته شده بود که چند تصویر مربوط به Brunner و یک دستور پخت محرمانه از شبکه ناپدید شده‌اند و در همان زمان، فعالیت شبکه‌ای مشکوکی هم دیده شده است.

فایل اصلی یک **PCAP کامل از شبکه** بود و یک نکته‌ی مهم هم داخل توضیحات وجود داشت:

> Please do not look at the pictures.

پس از همان اول احتمال می‌دادیم تصاویر بیشتر نقش حواس‌پرتی داشته باشند و باید روی ترافیک شبکه، مخصوصاً DNS، تمرکز کنیم.

---

## ۱. پیدا کردن ترافیک مشکوک

اول در Wireshark ترافیک DNS را بررسی کردیم و با فیلتر زیر رفتیم سراغ دامنه‌ای که در چند Query تکرار می‌شد:

```text
dns.qry.name contains "targ"
```

در نتیجه، Queryهای زیادی با دامنه‌ی زیر دیده شد:

```text
targwuwrnhos.com
```

بعضی Queryها عادی و قابل‌فهم بودند، مثل:

```text
update.targwuwrnhos.com
brunnerlocked.targwuwrnhos.com
```

اما بعضی دیگر Subdomainهای خیلی طولانی و کاملاً تصادفی داشتند، مثلاً:

```text
fc2s77jar2gqgafci4mbu4clou2gfciqcerci.targwuwrnhos.com
```

این الگو برای **DNS Exfiltration** بسیار مشکوک است؛ یعنی مهاجم داده را به‌جای اینکه مستقیماً روی شبکه بفرستد، داخل قسمت Subdomain کوئری‌های DNS تکه‌تکه می‌کند.

---

## ۲. فهمیدن اینکه Subdomainها Base32 هستند

وقتی به Subdomainها نگاه کردیم، تقریباً فقط این کاراکترها دیده می‌شد:

```text
A-Z
2-7
```

این دقیقاً الفبای Base32 است.

پس احتمال دادیم داده‌ی باینری به Base32 تبدیل شده و بعد داخل Queryهای DNS قرار گرفته است.

یک نکته‌ی مهم این بود که این Subdomainها **هر کدام یک Base32 مستقل نیستند**. در واقع هرکدام فقط یک تکه از یک رشته‌ی بزرگ‌تر هستند.

یعنی باید این کار را بکنیم:

```text
chunk1 + chunk2 + chunk3 + ...
                ↓
        یک Base32 stream
                ↓
          decode به بایت
```

نه اینکه هر Chunk را جداگانه Decode کنیم.

---

## ۳. اولین نشانه‌ی مهم بعد از Base32

تکه‌های اول را به ترتیب Packet در PCAP کنار هم گذاشتیم و Base32 را Decode کردیم.

برای اینکه مشکل Padding نداشته باشیم، از همان ایده‌ی Decoder دستی استفاده کردیم: هر کاراکتر Base32 را به ۵ بیت تبدیل کردیم و بیت‌ها را دوباره به بایت تقسیم کردیم.

نتیجه برای Stream اول این بود:

```text
122 bytes
```

و چهار بایت اول:

```text
28 b5 2f fd
```

این امضا مربوط به **Zstandard (Zstd)** است.

پس ساختار مرحله‌ی اول شد:

```text
DNS Query
   ↓
Base32
   ↓
Zstandard
   ↓
Text
```

---

## ۴. باز کردن Zstandard مرحله‌ی اول

داده‌ی Base32 Decode شده را با Zstd Decompress کردیم.

متن به‌دست‌آمده این بود:

```text
Tonight we'll encrypt their disks so they lose their Brunsviger cake recipe. brunner{k33p_53nd
Send the encryption key, and We include the IV
```

در اینجا دو چیز خیلی مهم فهمیدیم:

1. قسمتی از Flag همین‌جا آمده است:

```text
brunner{k33p_53nd
```

2. متن صریحاً می‌گوید یک **Encryption Key** و یک **IV** هم در ادامه وجود دارد.

پس هنوز Flag کامل نشده بود و باید سراغ Stage دوم می‌رفتیم.

---

## ۵. پیدا کردن Key از DNS TXT

کمی جلوتر در ترافیک، یک Query با نام زیر دیده شد:

```text
update.targwuwrnhos.com
```

و در پاسخ DNS یک TXT Record داشتیم که شامل این مقدار بود:

```text
KLUv/SAQgQAAQnJ1bm4zckszeUFFU0NCQw==
```

این رشته Base64 بود.

بعد از Base64 Decode، ابتدای داده دوباره با Zstd شروع می‌شد و بعد از Decompress، متن زیر به‌دست می‌آمد:

```text
Brunn3rK3yAESCBC
```

بنابراین AES Key را داشتیم:

```text
Brunn3rK3yAESCBC
```

نکته‌ی مهم: در PCAP اطلاعات دیگری مثل Passwordهای FTP هم وجود داشت، اما آن‌ها بخشی از مسیر اصلی رمزگشایی Flag نبودند. چیزی که برای AES لازم داشتیم همین Key بود.

---

## ۶. پیدا کردن Stage دوم

بعد از Queryهای `update`، دوباره تعداد زیادی Subdomain طولانی دیدیم. این‌ها تکه‌های دومین داده‌ی Exfil بودند.

تکه‌های Stage دوم را هم به ترتیب Packet کنار هم قرار دادیم.

اما اینجا به اولین مشکل واقعی برخوردیم.

اگر از Python استاندارد استفاده کنیم:

```python
base64.b32decode(...)
```

ممکن است با خطایی مثل:

```text
binascii.Error: Incorrect padding
```

مواجه شویم.

دلیلش این بود که رشته‌ی دوم از نظر طول، یک Base32 استاندارد با Padding معمولی نبود. بنابراین Decoder دستی دوستمان مناسب‌تر بود.

---

## ۷. یک اشتباه مهم در استخراج DNS

در اولین نسخه‌ی Solver، همه‌ی Queryهای دامنه‌ی `targwuwrnhos.com` را با هم جمع کردیم.

این کار اشتباه بود، چون Queryهایی مثل این‌ها هم وجود داشتند:

```text
update
brunnerlocked
```

این‌ها پیام‌های کنترلی یا Status بودند، نه Chunkهای داده.

مشکل جالب اینجا بود که `update` و `brunnerlocked` از حروفی ساخته شده‌اند که ظاهراً در الفبای Base32 هم هستند؛ بنابراین یک فیلتر ساده‌ی کاراکتری نمی‌توانست آن‌ها را حذف کند.

برای همین در Solver نهایی این پیام‌های مشخص را از جریان داده کنار گذاشتیم.

---

## ۸. تعداد Chunkها و دو Stage

بعد از فیلتر درست، ۱۵ Chunk داده‌ای داشتیم:

### Stage اول

۵ Chunk:

```text
1861
3566
6050
9133
10778
```

### Stage دوم

۱۰ Chunk:

```text
21517
21518
31524
31538
33444
35767
40289
40315
43783
43805
```

این تفکیک خیلی مهم بود؛ چون دو Stream مستقل داشتیم.

---

## ۹. Stage دوم هم Zstd بود

Stage دوم را هم با همان روش Decode کردیم.

چهار بایت اول دوباره این بودند:

```text
28 b5 2f fd
```

پس Stage دوم هم یک Zstandard frame بود.

این بار داده‌ی Decompress شده برابر بود با:

```text
256 bytes (طبق اطلاعات Frame)
```

اما PCAP فقط **265 بایت از Frame فشرده‌شده** در اختیار ما گذاشته بود و خود فریم در Capture کامل نبود. بنابراین Zstd هشدار می‌داد که Frame به انتها نرسیده است.

این بخش یکی از نکات مهم Challenge بود: نباید با دیدن خطای Zstd سریع نتیجه می‌گرفتیم که کل تحلیل اشتباه است.

---

## ۱۰. شناختن AES Container

داده‌ی قابل‌بازیابی Stage دوم به این شکل بود:

```text
05 a5 20 67 b8 cc 8a b3 7f 4d 6d f5 a1 54 09 f4
bb de b1 6f ...
```

می‌دانستیم AES در حالت CBC از یک **IV شانزده‌بایتی** استفاده می‌کند؛ چون اندازه‌ی Block در AES برابر 16 بایت است.

پس ساختار مورد انتظار را این‌طور امتحان کردیم:

```text
[16-byte IV][AES-CBC ciphertext]
```

در نتیجه IV شد:

```text
05a52067b8cc8ab37f4d6df5a15409f4
```

و بقیه‌ی داده را به‌عنوان Ciphertext در نظر گرفتیم.

---

## ۱۱. IV دقیقاً چیست؟

IV یا **Initialization Vector** مقداری است که در ابتدای بعضی حالت‌های رمزنگاری مثل CBC برای شروع زنجیره استفاده می‌شود.

در AES-CBC، بلوک اول چیزی شبیه این است:

```text
Ciphertext1 = AES(Plaintext1 XOR IV)
```

و بعد از آن هر بلوک با Ciphertext قبلی زنجیر می‌شود.

نکته‌ی مهم این است که:

```text
Key ≠ IV
```

در این Challenge:

```text
Key = Brunn3rK3yAESCBC
```

و:

```text
IV = 05a52067b8cc8ab37f4d6df5a15409f4
```

بود.

---

## ۱۲. یک تست خیلی خوب: اندازه‌ی Ciphertext

کل داده‌ی Decompress شده‌ی Stage دوم 256 بایت بود.

اگر 16 بایت اول را IV بگیریم:

```text
256 - 16 = 240
```

و:

```text
240 % 16 = 0
```

یعنی باقی‌مانده دقیقاً مضرب اندازه‌ی Block در AES است.

این یک نشانه‌ی بسیار خوب بود که ساختار را درست فهمیده‌ایم:

```text
16 bytes  → IV
240 bytes → AES ciphertext
```

---

## ۱۳. رمزگشایی AES-CBC

با Key و IV به‌دست‌آمده از PCAP، Stage دوم را به‌صورت AES-CBC باز کردیم.

در Python بخش اصلی به این شکل است:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = b"Brunn3rK3yAESCBC"
iv = data[:16]
ciphertext = data[16:]

cipher = AES.new(
    key,
    AES.MODE_CBC,
    iv
)

plaintext = cipher.decrypt(ciphertext)
plaintext = unpad(plaintext, AES.block_size)
```

رمزگشایی موفق بود و متن مرحله‌ی دوم را به ما داد.

این مرحله مهم‌ترین تأیید کل تحلیل بود؛ چون اگر Key، IV یا ترتیب داده‌ها اشتباه بود، AES به Plaintext معنادار نمی‌رسید.

---

## ۱۴. کنار هم گذاشتن Flag

از Stage اول داشتیم:

```text
brunner{k33p_53nd
```

و Stage دوم ادامه‌ی Flag را در اختیارمان گذاشت.

با کنار هم گذاشتن دو قسمت، Flag نهایی به دست آمد:

```text
brunner{k33p_53nd1ng_th3_me55ag3s}
```

---

## ۱۵. خلاصه‌ی مسیر حل

کل Challenge در نهایت این زنجیره بود:

```text
PCAP
 ↓
DNS Traffic
 ↓
targwuwrnhos.com
 ↓
DNS Exfiltration
 ↓
Base32
 ↓
2 × Zstandard frames
 ↓
Stage 1 → پیام + بخشی از Flag

Stage 2 → AES-CBC container
               ↓
      Key از DNS TXT
               ↓
      IV = 16 bytes
               ↓
      AES-CBC decrypt
               ↓
      ادامه‌ی Flag
```

---

## ۱۶. نکات مهمی که از این Challenge یاد گرفتیم

### DNS فقط برای Resolve کردن دامنه نیست

اگر Subdomainها خیلی بلند، تصادفی و مرتب باشند، باید احتمال **DNS Exfiltration** را جدی گرفت.

### هر Chunk لزوماً یک پیام مستقل نیست

در این Challenge هر Subdomain فقط یک تکه از یک Stream بزرگ‌تر بود. بنابراین باید Chunkها را به ترتیب Packet دوباره کنار هم گذاشت.

### Magic Numberها خیلی کمک می‌کنند

وجود:

```text
28 b5 2f fd
```

در ابتدای داده‌ی Decode شده، دلیل بسیار خوبی برای تشخیص Zstandard بود.

### خطای Parser لزوماً به معنی اشتباه بودن مسیر نیست

خطاهایی مثل:

```text
Incorrect padding
```

یا:

```text
Zstd decompression error
```

ممکن است از نحوه‌ی Reconstruct کردن داده یا ناقص بودن Capture باشند، نه اینکه کل فرضیه‌ی ما غلط باشد.

### Cryptography را با ساختار داده چک کنیم

در Stage دوم، اینکه بعد از کنار گذاشتن 16 بایت اول، Ciphertext دقیقاً مضربی از 16 بایت بود، یک نشانه‌ی مهم برای درست بودن ساختار بود.

---

## Flag

```text
brunner{k33p_53nd1ng_th3_me55ag3s}
```
