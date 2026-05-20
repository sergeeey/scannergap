# ScannerGap Pilot для МФО — Безопасный План Тестирования

## Контекст
- **Организации:** ТОО МФО «Финтех Финанс» + АО МФО «ОнлайнКазФинанс»
- **Тестируемое лицо:** Head of Internal & Economic Security (внутренний аудит)
- **Статус:** Internal POC, не external engagement
- **Цель:** Найти blind spots в security pipeline + первый case study для BlindSpotSec

---

## Фаза 1: Безопасная подготовка (День 1-2)

### Выбор scope (минимальный безопасный периметр)

**Опция A: Один критичный микросервис**
- Примеры: API авторизации, payment processing, KYC verification
- Объем: 1 репозиторий, 3-5 ключевых файлов
- Язык: Python/JavaScript (наиболее вероятно для МФО)

**Опция B: Один security-critical flow**
- Примеры: login flow, fund transfer, client data access
- Объем: 5-10 файлов вдоль flow (controller → service → DB)
- Фокус: input validation, auth checks, data sanitization

**Опция C: Public-facing endpoint set**
- Примеры: REST API endpoints для mobile app
- Объем: API routes + input handlers
- Фокус: injection, SSRF, auth bypass

**РЕКОМЕНДАЦИЯ:** Опция B (security-critical flow) — наиболее показательная для blind spot detection.

### Data handling (100% локально)

**Жёсткие правила безопасности:**
1. ✅ **Код НЕ покидает периметр МФО**
   - Все сканы запускаются на рабочей станции внутри МФО
   - Никаких cloud uploads, никаких external APIs
   - ScannerGap — fully local tool (Semgrep + Bandit локально)

2. ✅ **Zero production data**
   - Не сканируем production databases
   - Не трогаем production secrets (.env файлы)
   - Только source code (без credentials, без PII)

3. ✅ **Air-gap report**
   - Результаты сканов → sanitize перед sharing
   - Redact: функциональные имена, внутренние URLs, специфичные логики
   - Показывать только: CWE категории, паттерны, abstract examples

4. ✅ **Delete after audit**
   - После финального отчёта: удалить все scan outputs
   - Оставить только: high-level findings (без кода)
   - Retention: 0 дней для кода, permanent для sanitized findings

### Compliance checklist (до запуска)

- [ ] **Internal approval:** Нужно ли одобрение IT-директора/CEO?
  - Вероятно НЕТ (ты Head of Security, это твоя зона ответственности)
  - Но если есть InfoSec policy на code scanning → проверить

- [ ] **NDA status:** Есть ли NDA между тобой и МФО?
  - Вероятно покрыто employment contract
  - Если нет → создать простой internal memo "Security Audit Protocol"

- [ ] **Audit trail:** Задокументировать тест
  - Email/memo: "Провожу внутренний security audit на [repo name] с использованием open-source SAST tools"
  - Цель: due diligence, not rogue testing

---

## Фаза 2: Первый запуск (День 3-4)

### Шаг 1: Baseline сканирование

**Какие scanners у вас уже используются?**

Типичный stack для МФО:
- ❓ SonarQube / SonarCloud?
- ❓ GitHub Advanced Security (если код на GitHub)?
- ❓ Snyk / WhiteSource (dependency scanning)?
- ❓ Custom internal scripts?

**Если НЕТ текущих SAST scanners:**
→ Отлично! Это ещё больше ценности для BlindSpotSec (находим что вообще не видно)

**Если ЕСТЬ scanners:**
→ Идеально! Можно сравнить:
- Что находит текущий scanner
- Что находит ScannerGap detector (49 rules)
- **Q2 quadrant** = то что оба пропустили

### Шаг 2: ScannerGap detector запуск

```bash
# На рабочей станции внутри МФО
cd /path/to/target/repo

# Вариант 1: Прямой Semgrep scan
semgrep scan --config E:/scannergap/src/scannergap/detector/rules/ . --json > scannergap_output.json

# Вариант 2: Через ScannerGap wrapper script
python E:/scannergap/scripts/scan_local_project.py /path/to/target/repo --output results/mfo_pilot

# Вариант 3: Docker (если Semgrep не установлен локально)
python E:/scannergap/scripts/scan_local_project.py /path/to/target/repo --runner docker --output results/mfo_pilot
```

**Output:** `summary.md` с findings, каждый marked `REVIEW_CANDIDATE`

### Шаг 3: Manual triage (День 4)

**Для каждого finding:**
1. ✅ **Verify:** Это реальная уязвимость или false positive?
2. 🔍 **Root cause:** Почему текущий scanner (если есть) пропустил?
   - Тип blind spot: Type I (taint gap) / Type II (semantic) / Type III (unknown sink) / Type IV (partial bypass)
3. 📊 **Severity:** Critical / High / Medium / Low (по CVSS или внутренней шкале)
4. 🛠 **Remediation:** Конкретное действие (fix code / add rule / process change)

---

## Фаза 3: Отчёт и выводы (День 5-7)

### Внутренний отчёт для МФО (sanitized)

**Структура:**
```markdown
# Security Blind Spot Audit — [МФО Name] [Date]

## Executive Summary
- Scope: [repo/flow name, redacted]
- Method: ScannerGap detector (49 Semgrep rules) + manual review
- Findings: X REVIEW_CANDIDATE → Y confirmed → Z critical

## Coverage Matrix
| Scanner | Detected | Missed | Rate |
|---------|----------|--------|------|
| [Existing SAST if any] | N | M | X% |
| ScannerGap detector | N2 | M2 | Y% |
| Combined | N3 | M3 | Z% |

## Blind Spot Taxonomy
1. Type I (Cross-function taint): X findings
2. Type II (Semantic blindness): Y findings
3. Type III (Unknown sinks): Z findings
4. Type IV (Partial bypass): W findings

## Critical Findings (Top 3)
[Abstract examples, no real code]

1. **[CWE-XX] [Title]**
   - Impact: [severity]
   - Blind spot type: [I/II/III/IV]
   - Why missed: [technical reason]
   - Recommendation: [action]

## Next Steps
- [ ] Fix: [X critical findings]
- [ ] Add rules: [Y custom Semgrep rules для будущих сканов]
- [ ] Process change: [Z improvements to security pipeline]
- [ ] Expand audit: [other repos to scan]
```

### External case study для BlindSpotSec (ultra-sanitized)

**Можно публиковать (без NDA violation):**
- Industry: Microfinance
- Language: Python/JavaScript (generic)
- Findings: "X% blind spot rate in [generic category]"
- Taxonomy: Distribution по Type I-IV
- Abstract example: "Template injection in user-facing endpoint" (без кода)

**НЕ публиковать:**
- Название МФО
- Конкретные функции/переменные/URLs
- Внутренняя архитектура
- Количественные метрики (portfolio size, user count)

---

## Фаза 4: Масштабирование (если успешно)

### Вариант A: Expand внутри МФО
- Запустить на втором repo
- Scan на втором МФО (Финтех Финанс или ОнлайнКазФинанс)
- Quarterly recurring audit (как часть security pipeline)

### Вариант B: External pilot
- Если findings оказались ценными → предложить audit другим МФО в Казахстане
- Pricing: $500-1000 за scoped audit (как в poc-offer.md)
- Позиционирование: "Fractional CISO + AI-security audit"

### Вариант C: Product development
- Если blind spot rate >= 15% → pass Kill Criterion #1
- Если systematic clusters (3+ CWE categories) → pass Kill Criterion #2
- → Продолжить BlindSpotSec development до production benchmark

---

## Risk Mitigation

### Риск 1: False positives
**Mitigation:** Manual triage обязательна (не слепо trust scanner output)

### Риск 2: Data leak
**Mitigation:** 100% локальный запуск + sanitized reports + delete after audit

### Риск 3: Compliance violation
**Mitigation:** Internal audit memo + IT approval (если требуется)

### Риск 4: Time sink
**Mitigation:** Fixed scope (1 repo, 5 дней max) + kill criteria (если нет findings → stop)

### Риск 5: Conflict of interest
**Вопрос:** Можно ли Head of Security тестировать свой же internal tool на своей же организации?
**Ответ:** ДА, если:
- Цель = improve security (не personal profit)
- Результаты идут в benefit МФО (не только в BlindSpotSec marketing)
- Full transparency (если CEO/Board спросит → честный ответ)
- No external sales pitch без disclosure

---

## Success Metrics

**Для МФО:**
- ✅ Найдено ≥1 real vulnerability (critical or high)
- ✅ Улучшен security pipeline (custom rules / process change)
- ✅ Zero compliance violations в ходе теста

**Для BlindSpotSec:**
- ✅ First real-world case study (sanitized)
- ✅ Validation: blind spot rate >= 15%? (Kill Criterion #1)
- ✅ Potential first paying client (если МФО захочет recurring audit)

---

## Timeline (7 дней)

| День | Задача | Output |
|------|--------|--------|
| 1 | Выбор scope + data handling setup | Scope doc, approval (if needed) |
| 2 | Baseline scan (existing SAST if any) | Baseline report |
| 3 | ScannerGap detector run | Raw findings JSON |
| 4 | Manual triage + verification | Confirmed findings list |
| 5 | Internal report draft | Draft MD report |
| 6 | Review + remediation planning | Final internal report |
| 7 | Sanitized case study (if approved) | Public-safe version |

---

## Next Actions (сегодня)

1. **Выбери target repo** (1 критичный микросервис или flow)
2. **Проверь compliance** (нужно ли IT approval для internal security audit?)
3. **Установи Semgrep локально** (если ещё не установлен):
   ```bash
   pip install semgrep
   # OR if Windows environment issues:
   # Use Docker runner option from scan_local_project.py
   ```
4. **Запусти test scan** на маленьком test repo (не production):
   ```bash
   semgrep scan --config E:/scannergap/src/scannergap/detector/rules/ /path/to/test/repo
   ```
5. **Если работает → go for real pilot** (follow this plan)

---

**Автор:** Sergey Boyko  
**Дата:** 2026-05-20  
**Статус:** Draft (для internal review перед запуском)  
**Конфиденциальность:** Internal use only
