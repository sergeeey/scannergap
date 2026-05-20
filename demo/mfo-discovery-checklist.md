# МФО Discovery Checklist — Internal Security Audit

> **Контекст:** Internal POC (Head of Security тестирует tool на своей организации)  
> **Цель:** Собрать минимальную информацию перед запуском ScannerGap pilot

---

## 🎯 КРИТИЧНЫЕ ВОПРОСЫ (ответь ДО запуска)

### 1. Tech Stack & Codebase

**Какие языки программирования используются в МФО?**
- [ ] Python (backend/scripts)
- [ ] JavaScript/TypeScript (frontend/Node.js)
- [ ] Java/Kotlin (backend)
- [ ] C#/.NET (backend)
- [ ] PHP (legacy systems?)
- [ ] Go (microservices?)
- [ ] Другое: ___________

**Зачем важно:** ScannerGap detector имеет 49 rules для Python, JS, Java, PHP, Ruby. Если стек другой — detector будет менее эффективен.

**Главный вопрос себе:**
> "На каком языке написаны наши самые критичные сервисы (auth, payments, KYC)?"

---

### 2. Текущий Security Pipeline

**Какие SAST tools уже используются?**
- [ ] **Нет SAST** (сканируем вручную / code review only)
- [ ] **SonarQube** / SonarCloud
- [ ] **GitHub Advanced Security** (если код на GitHub)
- [ ] **Semgrep** (community / pro)
- [ ] **Bandit** (для Python)
- [ ] **ESLint** с security plugins (для JS)
- [ ] **CodeQL** (GitHub or self-hosted)
- [ ] **Snyk** / WhiteSource (dependency scanning)
- [ ] **Commercial SAST** (Checkmarx, Veracode, Fortify, etc.)
- [ ] **Custom scripts** (внутренние security checkers)

**Зачем важно:**
- Если НЕТ SAST → ScannerGap находит всё (baseline = 0)
- Если ЕСТЬ SAST → ScannerGap находит Q2 quadrant (что текущий scanner пропустил)

**Главный вопрос себе:**
> "Сколько раз за последний год мы находили уязвимости В PRODUCTION, которые НЕ поймал наш security pipeline?"

Если ≥1 раз → есть blind spots → ScannerGap будет полезен.

---

### 3. Target Scope (что сканировать ПЕРВЫМ)

**Вариант A: Критичный микросервис**
- Название: ___________
- Функция: (auth / payments / KYC / API gateway / другое)
- Язык: ___________
- Размер: ~_____ файлов
- Последний security incident: (да/нет, когда)

**Вариант B: Security-critical flow**
- Flow: (например, "user login → JWT issue → session management")
- Файлы вдоль flow: _____ (controller → service → DB → response)
- Язык: ___________
- Известные проблемы: (да/нет, какие)

**Вариант C: Public-facing API**
- API endpoints: _____ (например, /api/v1/auth, /api/v1/transactions)
- Framework: (FastAPI / Express / Spring Boot / другое)
- Язык: ___________
- Input validation: (есть/нет/частично)

**РЕКОМЕНДАЦИЯ для МФО:**
→ **Вариант B (security-critical flow)** — наиболее показательный для blind spot detection.

**Критерии выбора scope:**
1. ✅ **High impact если сломается** (auth > admin panel > reporting)
2. ✅ **User input присутствует** (больше attack surface)
3. ✅ **Недавние security concerns** (уже знаем что там проблемы)
4. ✅ **Небольшой размер** (5-15 файлов, не весь monolith)

**Главный вопрос себе:**
> "Если бы я был атакующим, какой сервис/flow я бы атаковал ПЕРВЫМ?"

---

### 4. Известные Security Pain Points

**Есть ли vulnerability classes, которые вы ЗНАЕТЕ что текущий pipeline пропускает?**

Примеры (отметь если актуально):
- [ ] **SQL injection** (особенно через ORM или stored procedures)
- [ ] **XSS** (особенно stored XSS или в admin панелях)
- [ ] **SSRF** (Server-Side Request Forgery — особенно в integrations)
- [ ] **Path traversal** (file upload/download endpoints)
- [ ] **Authentication bypass** (JWT issues, session fixation)
- [ ] **Authorization issues** (IDOR, privilege escalation)
- [ ] **Deserialization** (pickle, YAML.load, JSON deserialize)
- [ ] **Template injection** (Jinja2, Twig, FreeMarker)
- [ ] **Code injection** (eval, exec, dynamic imports)
- [ ] **Cryptographic issues** (weak algorithms, hardcoded keys)
- [ ] **Business logic flaws** (race conditions, amount manipulation)
- [ ] **API abuse** (rate limiting bypass, mass enumeration)

**Главный вопрос себе:**
> "Какие уязвимости мы находим В PRODUCTION чаще всего? Почему их не поймал SAST?"

---

### 5. Recent Security Incidents / Pentest Findings

**За последние 12 месяцев:**
- [ ] **Pentest проводился?** (да/нет, когда)
  - Если да: сколько findings было **High/Critical**? _____
  - Из них сколько **НЕ поймал SAST**? _____
  
- [ ] **Security incidents в production?** (да/нет)
  - Если да: какие типы? (injection / auth bypass / data leak / другое)
  
- [ ] **Bug bounty находки?** (если есть program)
  - Если да: какие категории чаще всего? _____

**Зачем важно:** Если pentest/incidents находят то что scanner пропустил → это прямое доказательство blind spots.

**Главный вопрос себе:**
> "Если бы мы прогнали ScannerGap ДО последнего pentest, нашли бы мы те же уязвимости?"

Если ответ "вероятно да" → ScannerGap окупится (дешевле чем pentest).

---

### 6. Access & Permissions

**Где хранится код?**
- [ ] **GitHub** (private repos)
- [ ] **GitLab** (self-hosted / cloud)
- [ ] **Bitbucket**
- [ ] **Azure DevOps**
- [ ] **On-premise Git server**
- [ ] **SVN** (legacy)
- [ ] **Local filesystems** (разработчики держат локально)

**У тебя есть прямой доступ к repos?**
- [ ] **ДА** (как Head of Security имею read access ко всем repos)
- [ ] **НЕТ** (нужно запросить у IT/DevOps)

**Если НЕТ прямого доступа:**
- Кто даёт доступ? ___________
- Сколько времени займёт approval? _____ (дни)
- Нужно ли обоснование? (да/нет)

**Главный вопрос себе:**
> "Могу ли я ПРЯМО СЕЙЧАС клонировать критичный repo и запустить scan? Или нужны permissions?"

---

### 7. Data Handling & Compliance

**Можно ли сканировать код ЛОКАЛЬНО (на рабочей станции внутри МФО)?**
- [ ] **ДА** (100% локально, ничего не выходит наружу)
- [ ] **НЕТ** (нужно согласование с compliance/legal)

**Есть ли в repos production secrets (.env, credentials)?**
- [ ] **ДА** (есть .env файлы с production DB passwords, API keys)
- [ ] **НЕТ** (secrets в отдельном vault — Vault, AWS Secrets Manager, etc.)
- [ ] **НЕ ЗНАЮ** (нужно проверить)

**Если ЕСТЬ secrets в repos:**
→ ScannerGap НЕ трогает .env файлы (только source code)
→ Но нужно убедиться что scan output не логирует secrets

**Compliance requirements:**
- [ ] **PCI DSS** (для card processing)
- [ ] **GDPR** (для EU clients, если есть)
- [ ] **Local regulations** (Kazakhstan financial regulations)
- [ ] **ISO 27001** (если сертифицированы)
- [ ] **SOC 2** (если планируете)

**Нужно ли InfoSec approval для internal security audit?**
- [ ] **НЕТ** (я Head of Security, это моя зона ответственности)
- [ ] **ДА** (нужно согласование с IT Director / CEO / Compliance)

**Главный вопрос себе:**
> "Если я прямо сейчас запущу Semgrep scan на production repo — кого мне нужно уведомить? Или я могу просто сделать?"

---

### 8. Expected Deliverables

**Что ты хочешь получить из pilot?**

Выбери приоритет (1 = самое важное, 3 = nice to have):
- [ ] **Blind spot taxonomy** (какие типы уязвимостей scanner пропускает)
  - Приоритет: _____
  
- [ ] **Coverage matrix** (что находит текущий scanner vs ScannerGap vs combined)
  - Приоритет: _____
  
- [ ] **Concrete findings** (список конкретных уязвимостей для fix)
  - Приоритет: _____
  
- [ ] **Custom Semgrep rules** (которые можно добавить в CI)
  - Приоритет: _____
  
- [ ] **Process recommendations** (как улучшить security pipeline)
  - Приоритет: _____
  
- [ ] **Executive summary** (для CEO/Board — "наш security pipeline имеет X% blind spot rate")
  - Приоритет: _____

**Кто будет читать final report?**
- [ ] Только ты (Head of Security)
- [ ] IT Director / CTO
- [ ] CEO
- [ ] Compliance Officer
- [ ] Dev Team Leads
- [ ] External auditors (если есть)

**Главный вопрос себе:**
> "Если ScannerGap найдёт 0 findings — это SUCCESS (наш pipeline good) или FAILURE (tool не работает)?"

Правильный ответ: **SUCCESS** — отсутствие findings тоже ценная информация.

---

### 9. Timeline & Effort

**Сколько времени ты можешь выделить на pilot?**
- [ ] **1-2 часа** (только запустить scan, посмотреть output)
- [ ] **1 день** (scan + quick triage)
- [ ] **3-5 дней** (scan + full triage + internal report)
- [ ] **1-2 недели** (scan + triage + report + remediation planning)

**Когда хочешь увидеть первые результаты?**
- [ ] **Сегодня** (quick scan прямо сейчас)
- [ ] **Эта неделя** (к пятнице)
- [ ] **Следующая неделя**
- [ ] **Не срочно** (когда будет время)

**РЕКОМЕНДАЦИЯ:**
→ **День 1-2:** Quick scan (2 часа)
→ **День 3-5:** Full pilot (если quick scan показал что-то интересное)

**Главный вопрос себе:**
> "Если ScannerGap найдёт 10 critical findings — когда я реально смогу их fix-ить?"

---

### 10. Success Criteria (определи ДО запуска)

**Pilot будет успешным если:**

Выбери ≥1 критерий:
- [ ] **Найдено ≥1 real vulnerability** (critical or high severity)
- [ ] **Найден ≥1 systematic blind spot** (целый класс уязвимостей)
- [ ] **Coverage matrix показала gaps** (понятно где текущий scanner слаб)
- [ ] **Получены actionable recommendations** (что конкретно делать дальше)
- [ ] **Доказано что pipeline уже good** (blind spot rate <5%, всё ок)

**Pilot будет провалом если:**
- [ ] **100% false positives** (все findings оказались ложными)
- [ ] **Всё уже известно** (scanner ничего нового не нашёл)
- [ ] **Слишком много noise** (1000+ findings, невозможно triage)
- [ ] **Tech stack mismatch** (rules не подходят для нашего языка/framework)

**Главный вопрос себе:**
> "При каком результате я скажу: 'ScannerGap стоит использовать регулярно'?"

---

## 📋 QUICK CHECKLIST (заполни за 5 минут)

Перед запуском pilot ответь на эти 5 вопросов:

1. **Язык главного сервиса:** ___________
2. **Есть ли текущий SAST?** (да/нет): _____
3. **Target scope:** (название repo/flow): ___________
4. **Прямой доступ к коду?** (да/нет): _____
5. **Timeline:** (когда хочу результаты): _____

Если все 5 ответов есть → **GO FOR PILOT** ✅

---

## 🚀 NEXT ACTIONS

После заполнения checklist:

1. ✅ **Если всё ясно** → запускай pilot по плану из `mfo-pilot-plan.md`
2. ⚠️ **Если нужны permissions** → запроси access к target repo
3. ⚠️ **Если нужно IT approval** → создай internal memo (template ниже)
4. 🛑 **Если tech stack mismatch** → обсуди альтернативы (maybe другой scanner?)

---

## 📄 TEMPLATE: Internal Audit Memo (если нужно IT approval)

```
To: [IT Director / CTO]
From: [Твоё имя], Head of Internal & Economic Security
Date: [сегодня]
Subject: Internal Security Audit — SAST Blind Spot Review

Purpose:
Conducting internal security audit using open-source SAST tools (Semgrep) to identify potential blind spots in our current security pipeline.

Scope:
- Target: [repo/service name]
- Method: Local scan on workstation (no external data transfer)
- Tools: Semgrep (open-source), ScannerGap detector rules
- Timeline: [X days]
- Output: Internal report with findings + recommendations

Data Handling:
- 100% local execution (no cloud uploads)
- Zero production data access
- Scan output sanitized before any sharing
- Delete working files after final report

Compliance:
- Standard security audit practice (due diligence)
- No regulatory violations
- Aligns with ISO 27001 / PCI DSS requirements (if applicable)

Approval Required: [Yes/No]
Expected Start: [date]

[Подпись]
```

---

**Автор:** Sergey Boyko  
**Дата:** 2026-05-20  
**Статус:** Discovery checklist для internal use  
**Конфиденциальность:** Internal only
